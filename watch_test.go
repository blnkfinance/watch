/*
Copyright 2024 Blnk Finance Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package watch

import (
	"errors"
	"testing"
)

type mockGlobalTunnel struct {
	hasSendAnomalyErr bool
}

func (m *mockGlobalTunnel) IsConnected() bool {
		return true
}

func (m *mockGlobalTunnel) SendAnomaly(anomaly AnomalyMessage) error {
	if m.hasSendAnomalyErr {
		return errors.New("mock send anomaly error")
	}
	return nil
}

// This type intentionally simulates when the globalTunnel has the IsConnected method but lacks the SendAnomaly method,
// in which case, it should trigger an error.
type mockGlobalTunnelLacksSendAnomaly struct{}

func (m *mockGlobalTunnelLacksSendAnomaly) IsConnected() bool {
	return true
}

func TestSendAnomalyToTunnel(t *testing.T) {
	originalGlobalTunnel := globalTunnel
	defer func() { 
		globalTunnel = originalGlobalTunnel 
	}()
	anomaly := AnomalyMessage{}
	tests := []struct{
		name string
		condition string
		globalTunnel interface{}
		hasError bool 
	} {
		{
			name: "nil globalTunnel",
			condition: "when globalTunnel is nil",
			globalTunnel: nil,
			hasError: true,
		},
		{
			name: "lacks isConnected",
			condition: "when globalTunnel lacks IsConnected method",
			globalTunnel: "Invalid Tunnel",
			hasError: true,
		},
		{
			name: "lacks sendAnomaly",
			condition: "when globalTunnel lacks SendAnomaly method",
			globalTunnel: &mockGlobalTunnelLacksSendAnomaly{},
			hasError: true,
		},
		{
			name: "sendAnomaly error",
			condition: "when SendAnomaly returns error",
			globalTunnel: &mockGlobalTunnel{hasSendAnomalyErr: true},
			hasError: true,
		},
		{
			name: "valid globalTunnel",
			condition: "when globalTunnel is totally valid",
			globalTunnel: &mockGlobalTunnel{},
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			globalTunnel = tt.globalTunnel
			err := SendAnomalyToTunnel(anomaly)
			if tt.hasError {
				if err == nil {
					t.Errorf("expected error %s, got none", tt.condition)
				}
				return
			}
			if err != nil {
				t.Errorf("expected no error %s, got: %s", tt.condition, err)
			}
		})
	}
}