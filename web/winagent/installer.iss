; RKMSIEM 윈도우 클라이언트 설치 마법사 (Inno Setup 6)
; 빌드: ISCC.exe /DAppVersion=57 installer.iss   (먼저 build-exe.py 로 dist\rkmsiem-winagent.exe 가 있어야 함)
; 결과: Output\rkmsiem-winagent-setup.exe  — 더블클릭하면 일반 프로그램처럼 설치 마법사 GUI

#ifndef AppVersion
  #define AppVersion "0"
#endif
#define AppName "RKMSIEM Agent"
#define AppExe "rkmsiem-winagent.exe"
#define TaskName "RKMSIEMAgent"

[Setup]
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=RKMSIEM
DefaultDirName={autopf}\RKMSIEM Agent
DefaultGroupName=RKMSIEM Agent
DisableProgramGroupPage=yes
OutputDir=Output
OutputBaseFilename=rkmsiem-winagent-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayName={#AppName}

[Languages]
Name: "ko"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "dist\{#AppExe}"; DestDir: "{app}"; Flags: ignoreversion

[UninstallRun]
Filename: "schtasks"; Parameters: "/delete /tn {#TaskName} /f"; Flags: runhidden; RunOnceId: "delagenttask"

[Code]
var
  ConnPage: TInputQueryWizardPage;
  OptPage: TInputOptionWizardPage;

procedure InitializeWizard;
begin
  ConnPage := CreateInputQueryPage(wpSelectDir,
    'RKMSIEM 서버 연결', 'SIEM 서버 정보를 입력하세요',
    '설치가 끝나면 이 값으로 자동 연결됩니다. 지문·등록 코드는 콘솔/서버에서 받습니다.');
  ConnPage.Add('서버 주소 (예: 10.0.0.53):', False);
  ConnPage.Add('포트:', False);
  ConnPage.Add('인증서 지문 (SHA-256, tls.sh --show):', False);
  ConnPage.Add('등록 코드 (rke_..., 콘솔 → 에이전트):', False);
  ConnPage.Values[1] := '8452';

  OptPage := CreateInputOptionPage(ConnPage.ID,
    '허용 조치', '이 PC 에서 서버가 할 수 있는 조치를 고르세요',
    '체크한 것만 허용됩니다 (서버가 털려도 그 밖의 일은 못 함).', False, False);
  OptPage.Add('프로세스 종료 (taskkill) 허용');
  OptPage.Add('서비스 재시작 (sc) 허용');
  OptPage.Add('보안 로그(실패 로그온) 서버로 보고');
  OptPage.Values[0] := True;
  OptPage.Values[1] := True;
  OptPage.Values[2] := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ConnPage.ID then begin
    if Trim(ConnPage.Values[0]) = '' then begin
      MsgBox('서버 주소를 입력하세요.', mbError, MB_OK); Result := False; Exit;
    end;
    if Trim(ConnPage.Values[3]) = '' then
      MsgBox('등록 코드가 비어 있습니다. 설치 후 설정 파일에 넣어도 됩니다.', mbInformation, MB_OK);
  end;
end;

function Allow(): String;
begin
  Result := '';
  if OptPage.Values[0] then Result := 'process_kill';
  if OptPage.Values[1] then begin
    if Result <> '' then Result := Result + ',';
    Result := Result + 'service_restart';
  end;
end;

procedure WriteConfig();
var
  dir, path, s, fp: String;
begin
  dir := ExpandConstant('{commonappdata}\RKMSIEM');
  CreateDir(dir);
  fp := Lowercase(Trim(ConnPage.Values[2]));
  StringChangeEx(fp, ':', '', True);
  s := '# RKMSIEM 윈도우 클라이언트 설정 (설치 마법사가 생성)' + #13#10
     + 'RKMSIEM_HOST=' + Trim(ConnPage.Values[0]) + #13#10
     + 'RKMSIEM_PORT=' + Trim(ConnPage.Values[1]) + #13#10
     + 'RKMSIEM_FINGERPRINT=' + fp + #13#10;
  if Trim(ConnPage.Values[3]) <> '' then
    s := s + 'ENROLL_CODE=' + Trim(ConnPage.Values[3]) + #13#10;
  s := s + 'ALLOW=' + Allow() + #13#10;
  if OptPage.Values[2] then s := s + 'TELEMETRY=1' + #13#10 else s := s + 'TELEMETRY=0' + #13#10;
  path := dir + '\winagent.env';
  SaveStringToFile(path, s, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  rc: Integer;
  exe: String;
begin
  if CurStep = ssPostInstall then begin
    WriteConfig();
    exe := ExpandConstant('{app}\{#AppExe}');
    // 부팅 시 SYSTEM 으로 자동 실행 (콘솔 exe 를 SCM 서비스로 올리는 배선보다 안정적)
    Exec('schtasks', '/create /tn {#TaskName} /tr """' + exe + '""" /sc onstart /ru SYSTEM /rl HIGHEST /f',
         '', SW_HIDE, ewWaitUntilTerminated, rc);
    Exec('schtasks', '/run /tn {#TaskName}', '', SW_HIDE, ewWaitUntilTerminated, rc);
  end;
end;
