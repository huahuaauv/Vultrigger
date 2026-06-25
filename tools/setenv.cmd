@echo off
set "TOOLS=%~dp0"
set "JAVA_HOME=%TOOLS%jdk8"
set "PATH=%JAVA_HOME%\bin;%PATH%"
for /f "delims=" %%D in ('dir /b /ad /o-n "%TOOLS%apache-maven-*" 2^>nul') do (
  set "MAVEN_HOME=%TOOLS%%%D"
  set "PATH=%MAVEN_HOME%\bin;%PATH%"
  goto :mvn_done
)
:mvn_done
echo JAVA_HOME=%JAVA_HOME%
echo MAVEN_HOME=%MAVEN_HOME%
java -version
call mvn -version
