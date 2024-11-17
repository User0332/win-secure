cd WinSecure.CSharp

dotnet build --configuration Release

cd..

copy-item WinSecure.CSharp/bin/Release/net47/WinSecure.CSharp.dll WinSecure.CSharp.dll
