// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.VisualStudio.Shell;

[assembly: AssemblyTitle("NuGet.Tools")]
[assembly: AssemblyDescription("Visual Studio Extensibility Package (vsix)")]
[assembly: ComVisible(false)]
[assembly: ProvideCodeBase(AssemblyName = "{AssemblyName}", Version = "{AssemblyVersion}", CodeBase = "$PackageFolder$\\{AssemblyFile}")]

