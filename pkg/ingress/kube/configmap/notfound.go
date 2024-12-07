// pkg/ingress/kube/configmap/notfound.go

package configmap

import (
    "github.com/alibaba/higress/pkg/ingress/kube/util"
    "istio.io/istio/pkg/config"
)

type NotFoundController struct {
    namespace string
    eventHandler ItemEventHandler
}

func NewNotFoundController(namespace string) *NotFoundController {
    return &NotFoundController{
        namespace: namespace,
    }
}

func (c *NotFoundController) GetName() string {
    return "notfound"
}

func (c *NotFoundController) AddOrUpdateHigressConfig(name util.ClusterNamespacedName, old *HigressConfig, new *HigressConfig) error {
    if old == nil && new == nil {
        return nil
    }
    
    // 配置发生变化时通知更新
    if c.eventHandler != nil {
        c.eventHandler(c.GetName())
    }
    return nil
}

func (c *NotFoundController) ValidHigressConfig(higressConfig *HigressConfig) error {
    if higressConfig == nil {
        return nil
    }
    
    if higressConfig.Gateway.NotFoundResponse != nil {
        if higressConfig.Gateway.NotFoundResponse.Enabled {
            if higressConfig.Gateway.NotFoundResponse.ContentType == "" {
                return fmt.Errorf("notfound response content type cannot be empty when enabled")
            }
            if higressConfig.Gateway.NotFoundResponse.Body == "" {
                return fmt.Errorf("notfound response body cannot be empty when enabled")
            }
        }
    }
    return nil
}

func (c *NotFoundController) ConstructEnvoyFilters() ([]*config.Config, error) {
    return nil, nil
}

func (c *NotFoundController) RegisterItemEventHandler(handler ItemEventHandler) {
    c.eventHandler = handler
}