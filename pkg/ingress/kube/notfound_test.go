// pkg/ingress/kube/configmap/notfound_test.go

package configmap

import (
    "testing"

    "github.com/alibaba/higress/pkg/ingress/kube/util"
    "github.com/stretchr/testify/assert"
)

func TestNotFoundController(t *testing.T) {
    // 创建控制器实例
    controller := NewNotFoundController("test-namespace")

    // 测试用例
    testCases := []struct {
        name          string
        config        *HigressConfig
        expectError   bool
        errorContains string
    }{
        {
            name:          "nil config",
            config:        nil,
            expectError:   false,
        },
        {
            name: "valid config",
            config: &HigressConfig{
                Gateway: Gateway{
                    NotFoundResponse: &NotFoundConfig{
                        Enabled:     true,
                        ContentType: "text/html",
                        Body:        "<html><body>404</body></html>",
                    },
                },
            },
            expectError: false,
        },
        {
            name: "missing content type",
            config: &HigressConfig{
                Gateway: Gateway{
                    NotFoundResponse: &NotFoundConfig{
                        Enabled: true,
                        Body:    "<html><body>404</body></html>",
                    },
                },
            },
            expectError:   true,
            errorContains: "content type cannot be empty",
        },
        {
            name: "missing body",
            config: &HigressConfig{
                Gateway: Gateway{
                    NotFoundResponse: &NotFoundConfig{
                        Enabled:     true,
                        ContentType: "text/html",
                    },
                },
            },
            expectError:   true,
            errorContains: "body cannot be empty",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            err := controller.ValidHigressConfig(tc.config)
            if tc.expectError {
                assert.Error(t, err)
                if tc.errorContains != "" {
                    assert.Contains(t, err.Error(), tc.errorContains)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

func TestConfigmapMgr_NotFoundConfig(t *testing.T) {
    // 创建 ConfigmapMgr 实例
    mgr := &ConfigmapMgr{
        Namespace: "test-namespace",
        higressConfig: atomic.Value{},
    }

    // 测试用例
    testCases := []struct {
        name           string
        config         *HigressConfig
        expectType     string
        expectBody     string
    }{
        {
            name: "enabled config",
            config: &HigressConfig{
                Gateway: Gateway{
                    NotFoundResponse: &NotFoundConfig{
                        Enabled:     true,
                        ContentType: "text/html",
                        Body:        "<html><body>Custom 404</body></html>",
                    },
                },
            },
            expectType: "text/html",
            expectBody: "<html><body>Custom 404</body></html>",
        },
        {
            name: "disabled config",
            config: &HigressConfig{
                Gateway: Gateway{
                    NotFoundResponse: &NotFoundConfig{
                        Enabled:     false,
                        ContentType: "text/html",
                        Body:        "<html><body>Custom 404</body></html>",
                    },
                },
            },
            expectType: "",
            expectBody: "",
        },
        {
            name:       "nil config",
            config:     nil,
            expectType: "",
            expectBody: "",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            mgr.SetHigressConfig(tc.config)

            contentType := mgr.GetNotFoundContentType()
            assert.Equal(t, tc.expectType, contentType)

            body := mgr.GetNotFoundBody()
            assert.Equal(t, tc.expectBody, body)
        })
    }
}

func TestNotFoundController_EventHandler(t *testing.T) {
    controller := NewNotFoundController("test-namespace")
    
    // 测试事件处理
    var handlerCalled bool
    var handlerName string
    
    controller.RegisterItemEventHandler(func(name string) {
        handlerCalled = true
        handlerName = name
    })

    // 测试配置更新触发事件
    err := controller.AddOrUpdateHigressConfig(
        util.ClusterNamespacedName{
            Namespace: "test-namespace",
            Name:     "test-config",
        },
        nil,
        &HigressConfig{
            Gateway: Gateway{
                NotFoundResponse: &NotFoundConfig{
                    Enabled:     true,
                    ContentType: "text/html",
                    Body:        "<html><body>404</body></html>",
                },
            },
        },
    )

    assert.NoError(t, err)
    assert.True(t, handlerCalled)
    assert.Equal(t, "notfound", handlerName)
}