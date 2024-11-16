#Milan is testing

using namespace System;
using namespace System.Reflection;
using namespace System.Collections.Generic;

$assemblyPath = Join-Path $PSScriptRoot "WinSecure.CSharp.dll"

$securingAsm = [Assembly]::LoadFrom($assemblyPath);

$mainClass = $securingAsm.GetType("WinSecure.CSharp.SecureMain");

$mainMethod = $mainClass.GetMethod("Main", [BindingFlags]::Public -bor [BindingFlags]::Static);

$argsToPass = [List[Object]]::new(1);

$argsToPass.Add([string[]] $args);

$retcode = $mainMethod.Invoke($null, $argsToPass.ToArray());

exit $retcode