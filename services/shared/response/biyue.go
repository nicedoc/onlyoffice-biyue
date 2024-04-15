/**
 *
 * (c) Copyright Ascensio System SIA 2023
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package response

// "sub": "5f92cb9f-20df-4f5b-b52a-ffd080be579c",
// "email_verified": false,
// "name": "Mingyuan Hou",
// "preferred_username": "biyue",
// "given_name": "Mingyuan",
// "family_name": "Hou",
// "email": "houmingyuan@gmail.com"
type BiyueUserResponse struct {
	AccountID string `json:"sub"`
	Email     string `json:"email"`
	BiyueUserName
	Locale string `json:"locale"`
}

type BiyueUserName struct {
	DisplayName  string `json:"preferred_username"`
	FamiliarName string `json:"family_name"`
	GivenName    string `json:"given_name"`
	Surname      string `json:"surname"`
}

type BiyueFileResponse struct {
	ID          string `json:"id"`
	CModified   string `json:"client_modified"`
	SModified   string `json:"server_modified"`
	PathLower   string `json:"path_lower"`
	PathDisplay string `json:"path_display"`
	Rev         string `json:"rev"`
	Name        string `json:"name"`
	Size        int    `json:"size"`
}

type BiyueDownloadResponse struct {
	Link string `json:"link"`
}
