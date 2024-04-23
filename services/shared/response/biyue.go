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
	UserID     string `json:"user_id"`     // 用户ID
	SchoolID   uint32 `json:"school_id"`   // 学校ID
	SchoolName string `json:"school_name"` // 学校姓名
	PersonID   uint32 `json:"person_id"`   // 人员ID
	PersonName string `json:"person_name"` // 人员姓名
	Locale     string `json:"locale"`      // 语言 default zh-CN
}

type BiyueUserName struct {
	DisplayName  string `json:"preferred_username"`
	FamiliarName string `json:"family_name"`
	GivenName    string `json:"given_name"`
	Surname      string `json:"surname"`
}

type BiyueFileResponse struct {
	PaperUuid   string `json:"paper_uuid"`      // 试卷的文件id
	CModified   string `json:"client_modified"` // 客户端最后修改时间：格式2022-08-23 01:02:03
	SModified   string `json:"server_modified"` // 服务端最后修改时间：格式2022-08-23 01:02:03
	PathLower   string `json:"path_lower"`      // 文件路径（path_display的小写）
	PathDisplay string `json:"path_display"`    // 显示路径（bucket里的相对路径）
	Rev         string `json:"rev"`             // 对象版本号
	Name        string `json:"name"`            // 文件名
	Size        int    `json:"size"`            // 文件大小，单位bytes
}

type BiyueDownloadResponse struct {
	Link string `json:"link"`
}
