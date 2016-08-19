//
//Copyright [2016] [SnapRoute Inc]
//
//Licensed under the Apache License, Version 2.0 (the "License");
//you may not use this file except in compliance with the License.
//You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//	 Unless required by applicable law or agreed to in writing, software
//	 distributed under the License is distributed on an "AS IS" BASIS,
//	 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	 See the License for the specific language governing permissions and
//	 limitations under the License.
//
//   This is a auto-generated file, please do not edit!
// _______   __       __________   ___      _______.____    __    ____  __  .___________.  ______  __    __  
// |   ____||  |     |   ____\  \ /  /     /       |\   \  /  \  /   / |  | |           | /      ||  |  |  | 
// |  |__   |  |     |  |__   \  V  /     |   (----  \   \/    \/   /  |  |  ---|  |---- |  ,---- |  |__|  | 
// |   __|  |  |     |   __|   >   <       \   \      \            /   |  |     |  |     |  |     |   __   | 
// |  |     |  `----.|  |____ /  .  \  .----)   |      \    /\    /    |  |     |  |     |  `----.|  |  |  | 
// |__|     |_______||_______/__/ \__\ |_______/        \__/  \__/     |__|     |__|      \______||__|  |__| 
//                                                                                                           
		
namespace go isisd
typedef i32 int
typedef i16 uint16
struct IsisGlobal {
	1 : string Vrf
	2 : bool Enable
}
struct IsisGlobalState {
	1 : string Vrf
	2 : bool Enable
}
struct IsisGlobalStateGetInfo {
	1: int StartIdx
	2: int EndIdx
	3: int Count
	4: bool More
	5: list<IsisGlobalState> IsisGlobalStateList
}

struct PatchOpInfo {
    1 : string Op
    2 : string Path
    3 : string Value
}
			        
service ISISDServices {
	bool CreateIsisGlobal(1: IsisGlobal config);
	bool UpdateIsisGlobal(1: IsisGlobal origconfig, 2: IsisGlobal newconfig, 3: list<bool> attrset, 4: list<PatchOpInfo> op);
	bool DeleteIsisGlobal(1: IsisGlobal config);

	IsisGlobalStateGetInfo GetBulkIsisGlobalState(1: int fromIndex, 2: int count);
	IsisGlobalState GetIsisGlobalState(1: string Vrf);
}