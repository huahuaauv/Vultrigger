$Tools = Split-Path -Parent $MyInvocation.MyCommand.Path
$Jdk = Join-Path $Tools "jdk8"
$JavaExe = Join-Path $Jdk "bin\java.exe"
if (Test-Path $JavaExe) {
    $env:JAVA_HOME = $Jdk
    $env:PATH = (Join-Path $Jdk "bin") + ";" + $env:PATH
}
$MavenDirs = Get-ChildItem -Path $Tools -Directory -Filter "apache-maven-*" | Sort-Object Name -Descending
foreach ($d in $MavenDirs) {
    $mvn = Join-Path $d.FullName "bin\mvn.cmd"
    if (Test-Path $mvn) {
        $env:MAVEN_HOME = $d.FullName
        $env:PATH = (Join-Path $d.FullName "bin") + ";" + $env:PATH
        break
    }
}
Write-Host "JAVA_HOME=$env:JAVA_HOME"
Write-Host "MAVEN_HOME=$env:MAVEN_HOME"
java -version 2>&1
mvn -version
