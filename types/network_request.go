// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Generated by: OpenAPI Generator (https://openapi-generator.tech)

package types

import "encoding/json"

// NetworkRequest A NetworkRequest is utilized to retrieve some data specific exclusively to a
// NetworkIdentifier.
type NetworkRequest struct {
	NetworkIdentifier *NetworkIdentifier `json:"network_identifier"`
	Metadata          json.RawMessage    `json:"metadata,omitempty"`
}
