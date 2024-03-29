// Copyright 2024, Ryan Parman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package dockerfile_hasher is a package that provides the ability to read a
Dockerfile from disk, parse it into an Abstract Syntax Tree (AST), and then
rewrite the lines in the Dockerfile with the SHA256 digest of the image.

Supports logging with the https://github.com/rs/zerolog package.
*/
package dockerfile_hasher
