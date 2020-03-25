# UnixPermission

A simple Unix permissions parser and calculator.

### Usage

Parse and read unix file permissions given the mode or symbolic string:

```kotlin
UnixPermission.parse("0755").permissions // rwxr-xr-x
UnixPermission.parse("rw-r--r--").octal  // 0644
```

### Copyright

```
Copyright (C) 2020 Jared Rummler

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```