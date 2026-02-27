package syncers

import (
	"fmt"
	"strings"

	"github.com/loft-sh/vcluster/pkg/syncer"
	"github.com/loft-sh/vcluster/pkg/syncer/synccontext"
	"github.com/loft-sh/vcluster/pkg/syncer/translator"
	synctypes "github.com/loft-sh/vcluster/pkg/syncer/types"
	"github.com/loft-sh/vcluster/pkg/util/translate"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	vImportedAnnotation = "vcluster.loft.sh/imported"
	pImportAnnotation   = "vcluster.loft.sh/import"
)

func NewImportSecrets(ctx *synccontext.RegisterContext) synctypes.Base {
	mapper, err := ctx.Mappings.ByGVK(corev1.SchemeGroupVersion.WithKind("Secret"))
	if err != nil {
		klog.FromContext(ctx).Error(err, "unable to get mapping for corev1.Secret")
		return nil
	}

	return &importSecretSyncer{
		GenericTranslator: translator.NewGenericTranslator(ctx, "import-secret", &corev1.Secret{}, mapper),
	}
}

type importSecretSyncer struct {
	synctypes.GenericTranslator
}

func (s *importSecretSyncer) Syncer() synctypes.Sync[client.Object] {
	return syncer.ToGenericSyncer[*corev1.Secret](s)
}

var _ synctypes.Syncer = &importSecretSyncer{}

func (s *importSecretSyncer) SyncToVirtual(ctx *synccontext.SyncContext, event *synccontext.SyncToVirtualEvent[*corev1.Secret]) (ctrl.Result, error) {
	pSecret := event.Host
	if pSecret == nil {
		return ctrl.Result{}, nil
	}

	// ignore Secrets synced to the host by the vcluster
	if pSecret.Labels != nil && pSecret.Labels[translate.MarkerLabel] != "" {
		return ctrl.Result{}, nil
	}

	// try to parse import annotation
	namespaceName := parseFromAnnotation(pSecret.Annotations, pImportAnnotation)
	if namespaceName.Name == "" {
		return ctrl.Result{}, nil
	}

	// check if namespace is there
	err := ctx.VirtualClient.Get(ctx.Context, types.NamespacedName{Name: namespaceName.Namespace}, &corev1.Namespace{})
	if err != nil {
		if !kerrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}

		// create namespace
		ctx.Log.Infof("create namespace %s", namespaceName.Namespace)
		err = ctx.VirtualClient.Create(ctx.Context, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespaceName.Namespace}})
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("creating namespace %s: %w", namespaceName.Namespace, err)
		}
	}

	// create virtual secret
	vSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   namespaceName.Namespace,
			Name:        namespaceName.Name,
			Annotations: getVirtualAnnotations(pSecret),
			Labels:      pSecret.Labels,
		},
		Immutable: pSecret.Immutable,
		Data:      pSecret.Data,
		Type:      pSecret.Type,
	}
	ctx.Log.Infof("import secret %s/%s into %s/%s", pSecret.GetNamespace(), pSecret.GetName(), vSecret.Namespace, vSecret.Name)
	err = ctx.VirtualClient.Create(ctx.Context, vSecret)
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to import secret %s/%s: %v", pSecret.GetNamespace(), pSecret.GetName(), err)
	}

	return ctrl.Result{}, err
}

func (s *importSecretSyncer) Sync(ctx *synccontext.SyncContext, event *synccontext.SyncEvent[*corev1.Secret]) (ctrl.Result, error) {
	pSecret := event.Host
	vSecret := event.Virtual
	if pSecret == nil || vSecret == nil {
		return ctrl.Result{}, nil
	}

	// check if we should delete secret
	vSecretName := parseFromAnnotation(pSecret.Annotations, pImportAnnotation)
	if vSecretName.Name == "" {
		// delete synced secret if the physical secret is not referencing it anymore
		ctx.Log.Infof("delete virtual secret %s/%s because host secret is no longer pointing to it", vSecret.GetNamespace(), vSecret.GetName())
		err := ctx.VirtualClient.Delete(ctx.Context, vSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to delete imported secret %s/%s: %v", vSecret.GetNamespace(), vSecret.GetName(), err)
		}

		return ctrl.Result{}, err
	}

	// check if update is needed
	updated := s.translateUpdateUp(pSecret, vSecret)
	if updated == nil {
		// no update is needed
		return ctrl.Result{}, nil
	}

	// update secret
	ctx.Log.Infof("update imported secret %s/%s", vSecret.GetNamespace(), vSecret.GetName())
	err := ctx.VirtualClient.Update(ctx.Context, updated)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to update imported secret %s/%s: %v", vSecret.GetNamespace(), vSecret.GetName(), err)
	}

	return ctrl.Result{}, err
}

func (s *importSecretSyncer) SyncToHost(ctx *synccontext.SyncContext, event *synccontext.SyncToHostEvent[*corev1.Secret]) (ctrl.Result, error) {
	vObj := event.Virtual
	if vObj == nil {
		return ctrl.Result{}, nil
	}

	// this is called when the secret in the host gets removed
	// or if the vObj is an unrelated Secret created in vcluster

	// check if this particular secret was created by this plugin
	if parseFromAnnotation(vObj.GetAnnotations(), vImportedAnnotation).Name != "" {
		// delete synced secret because the host secret was deleted
		ctx.Log.Infof("delete imported secret %s/%s because host secret no longer exists", vObj.GetNamespace(), vObj.GetName())
		err := ctx.VirtualClient.Delete(ctx.Context, vObj)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to delete pull secret %s/%s: %v", vObj.GetNamespace(), vObj.GetName(), err)
		}
	}

	// ignore all unrelated Secrets
	return ctrl.Result{}, nil
}

// IsManaged determines if a physical object is managed by the vcluster
func (s *importSecretSyncer) IsManaged(ctx *synccontext.SyncContext, pObj client.Object) (bool, error) {
	// check in multi namespace mode
	if !translate.Default.IsTargetedNamespace(ctx, pObj.GetNamespace()) {
		return false, nil
	}

	return parseFromAnnotation(pObj.GetAnnotations(), pImportAnnotation).Name != "", nil
}

// VirtualToHost translates a virtual name to a physical name
func (s *importSecretSyncer) VirtualToHost(ctx *synccontext.SyncContext, req types.NamespacedName, vObj client.Object) types.NamespacedName {
	if vObj == nil {
		return types.NamespacedName{}
	}

	// exclude all objects that are not part of the vCluster namespace
	name := parseFromAnnotation(vObj.GetAnnotations(), vImportedAnnotation)
	if !translate.Default.IsTargetedNamespace(ctx, name.Namespace) {
		return types.NamespacedName{}
	}

	return name
}

// HostToVirtual translates a physical name to a virtual name
func (s *importSecretSyncer) HostToVirtual(ctx *synccontext.SyncContext, req types.NamespacedName, pObj client.Object) types.NamespacedName {
	if pObj == nil {
		return types.NamespacedName{}
	}

	return parseFromAnnotation(pObj.GetAnnotations(), pImportAnnotation)
}

func (s *importSecretSyncer) translateUpdateUp(pObj, vObj *corev1.Secret) *corev1.Secret {
	var updated *corev1.Secret

	// check annotations
	expectedAnnotations := getVirtualAnnotations(pObj)
	if !equality.Semantic.DeepEqual(vObj.GetAnnotations(), expectedAnnotations) {
		if updated == nil {
			updated = vObj.DeepCopy()
		}
		updated.Annotations = expectedAnnotations
	}

	// check labels
	if !equality.Semantic.DeepEqual(vObj.GetLabels(), pObj.GetLabels()) {
		if updated == nil {
			updated = vObj.DeepCopy()
		}
		updated.Labels = pObj.GetLabels()
	}

	// check data
	if !equality.Semantic.DeepEqual(vObj.Data, pObj.Data) {
		if updated == nil {
			updated = vObj.DeepCopy()
		}
		updated.Data = pObj.Data
	}

	return updated
}

func getVirtualAnnotations(pSecret *corev1.Secret) map[string]string {
	annotations := map[string]string{}
	for k, v := range pSecret.Annotations {
		if k == pImportAnnotation {
			continue
		}

		annotations[k] = v
	}

	annotations[vImportedAnnotation] = pSecret.Namespace + "/" + pSecret.Name
	return annotations
}

func parseFromAnnotation(annotations map[string]string, annotation string) types.NamespacedName {
	if annotations == nil || annotations[annotation] == "" {
		return types.NamespacedName{}
	}

	splitted := strings.Split(annotations[annotation], "/")
	if len(splitted) != 2 {
		klog.Infof("Retrieved malformed import annotation %s: %s, expected NAMESPACE/NAME", annotation, annotations[annotation])

		return types.NamespacedName{}
	}

	return types.NamespacedName{
		Namespace: splitted[0],
		Name:      splitted[1],
	}
}
