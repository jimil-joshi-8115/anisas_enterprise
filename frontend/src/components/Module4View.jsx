import React from 'react';
import { Eye, Video, Bug, Key, ArrowRight, ListFilter, Radio, ShieldAlert, Cpu, Sparkles } from 'lucide-react';

export default function Module4View({ onNavigate }) {
  return (
    <div className="space-y-6 font-mono text-xs">
      
      {/* Module Header */}
      <div className="soc-card p-6 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="text-xs text-[#FFB800] font-bold uppercase tracking-wider">
            MODULE 04 • SURVEILLANCE & IOT ASSET INTELLIGENCE OUTPUT
          </div>
          <h1 className="text-2xl font-black text-white tracking-wide mt-1 font-sans">
            Surveillance Systems & IoT Inventory
          </h1>
          <p className="text-xs text-slate-400 mt-1 font-sans">
            Discovers CCTV, IP Cameras, NVR/DVR Reconnaissance, ONVIF/RTSP Streams, Embedded Web Consoles, CVE Vulnerabilities, and Default Credentials.
          </p>
        </div>
        <button
          onClick={() => onNavigate('module5')}
          className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-white font-black text-xs tracking-wider uppercase flex items-center space-x-2 shadow-lg shadow-amber-500/20 transition cursor-pointer shrink-0"
        >
          <span>PASS OUTPUT TO MODULE 05 AI RISK ENGINE</span>
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>DISCOVERED IOT ASSETS</span>
            <Video className="w-4 h-4 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-black text-[#FFB800] tracking-tight">1 Asset</div>
          <div className="text-xs text-slate-400">Embedded IoT / Camera</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>HARDWARE VENDOR</span>
            <Eye className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-black text-blue-400 tracking-tight">Hikvision Digital</div>
          <div className="text-xs text-slate-400">ONVIF / OUI Signature</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>CORRELATED CVES</span>
            <Bug className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-black text-rose-400 tracking-tight">2 CVE Matches</div>
          <div className="text-xs text-rose-400 font-bold">Firmware Vulnerabilities</div>
        </div>

        <div className="soc-card p-5 space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase tracking-wider">
            <span>DEFAULT CREDENTIAL FLAGS</span>
            <Key className="w-4 h-4 text-[#FFB800]" />
          </div>
          <div className="text-2xl font-black text-[#FFB800] tracking-tight">2 Known Sets</div>
          <div className="text-xs text-slate-400">Defensive Awareness Only</div>
        </div>
      </div>

      {/* DISCOVERED SURVEILLANCE HARDWARE Table */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <ListFilter className="w-4 h-4 text-[#FFB800]" />
            <span>DISCOVERED SURVEILLANCE HARDWARE & EMBEDDED IOT INVENTORY</span>
          </h3>
          <span className="text-[11px] text-[#00F0FF]">MAC Vendor OUI & Passive Fingerprint</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-500 uppercase text-[10px]">
                <th className="py-3 px-4">TARGET IP</th>
                <th className="py-3 px-4">DEVICE CATEGORY</th>
                <th className="py-3 px-4">VENDOR & MODEL</th>
                <th className="py-3 px-4">FIRMWARE VERSION</th>
                <th className="py-3 px-4">EMBEDDED SERVER</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1E293B]/60 text-slate-300">
              <tr className="hover:bg-slate-900/50 transition">
                <td className="py-3.5 px-4 text-[#00F0FF] font-bold">187.245.231.228</td>
                <td className="py-3.5 px-4">
                  <span className="px-2.5 py-1 rounded bg-[#FFB800]/20 text-[#FFB800] border border-[#FFB800]/40 text-[10px] font-bold">
                    SURVEILLANCE_CAMERA_DVR
                  </span>
                </td>
                <td className="py-3.5 px-4 font-bold text-white">
                  Hikvision Digital Technology (DS-2CD2143G0-I)
                </td>
                <td className="py-3.5 px-4 text-slate-300">
                  V5.5.80 build 200316
                </td>
                <td className="py-3.5 px-4 text-slate-300">
                  Embedded Web Server
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* ONVIF & RTSP STREAM ENDPOINTS Panel */}
      <div className="soc-card p-6 space-y-6">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <Radio className="w-4 h-4 text-[#00F0FF]" />
            <span>ONVIF & RTSP STREAM ENDPOINTS</span>
          </h3>
          <span className="text-[11px] text-slate-400">Passive Protocol Audit</span>
        </div>

        {/* RTSP Sub-Block */}
        <div className="soc-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#00F0FF] uppercase flex items-center space-x-2">
              <Video className="w-4 h-4" />
              <span>Live RTSP Stream Endpoints</span>
            </span>
            <span className="px-2 py-0.5 bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 rounded text-[10px] font-bold">
              RTSP / 554
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div>
              <span className="text-slate-400 block text-[10px]">Primary High-Res Stream:</span>
              <code className="text-[#00F0FF] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                rtsp://187.245.231.228:554/Streaming/Channels/101
              </code>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Secondary Sub-Stream:</span>
              <code className="text-[#00F0FF] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                rtsp://187.245.231.228:554/Streaming/Channels/102
              </code>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Audio Stream:</span>
              <code className="text-[#00F0FF] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                rtsp://187.245.231.228:554/Streaming/Channels/101/audio
              </code>
            </div>
            <div className="text-[11px] text-slate-400 pt-1">
              Codecs: H.264 / HEVC Main (4K 30fps) + H.264 / AAC + AAC Audio
            </div>
          </div>
        </div>

        {/* ONVIF Sub-Block */}
        <div className="soc-card p-5 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-[#10B981] uppercase flex items-center space-x-2">
              <Eye className="w-4 h-4" />
              <span>ONVIF PROTOCOL ENDPOINTS</span>
            </span>
            <span className="px-2 py-0.5 bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40 rounded text-[10px] font-bold">
              ONVIF / 80
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div>
              <span className="text-slate-400 block text-[10px]">Device Service Endpoint:</span>
              <code className="text-[#10B981] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                http://187.245.231.228:80/onvif/device_service
              </code>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Media Service Endpoint:</span>
              <code className="text-[#10B981] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                http://187.245.231.228:80/onvif/media_service
              </code>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">PTZ Camera Control Service:</span>
              <code className="text-[#10B981] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                http://187.245.231.228:80/onvif/ptz_service
              </code>
            </div>
            <div>
              <span className="text-slate-400 block text-[10px]">Snapshot Image URL:</span>
              <code className="text-[#10B981] bg-[#060913] px-3 py-1.5 rounded-lg border border-[#1E293B] block font-mono mt-0.5">
                http://187.245.231.228:80/onvif/media/snapshot.jpg
              </code>
            </div>

            {/* Profile Badges */}
            <div className="flex flex-wrap gap-2 pt-2">
              <span className="px-2.5 py-1 bg-cyan-950 text-cyan-300 border border-cyan-800 rounded text-[10px] font-bold">Profile S (Streaming)</span>
              <span className="px-2.5 py-1 bg-blue-950 text-blue-300 border border-blue-800 rounded text-[10px] font-bold">Profile T (H.265)</span>
              <span className="px-2.5 py-1 bg-indigo-950 text-indigo-300 border border-indigo-800 rounded text-[10px] font-bold">Profile G (Edge Storage)</span>
              <span className="px-2.5 py-1 bg-purple-950 text-purple-300 border border-purple-800 rounded text-[10px] font-bold">Profile M (AI Analytics)</span>
            </div>
          </div>
        </div>

      </div>

      {/* CVE MATCHES & DEFAULT CREDENTIALS Cards */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>CVE MATCHES & DEFAULT CREDENTIALS</span>
          </h3>
          <span className="text-[11px] text-[#FFB800]">Defensive Assessment</span>
        </div>

        <div className="space-y-3">
          {/* Dynamic Vendor Confirmation Check for CVE Matches */}
          {hasRealAsset && hardwareVendor !== "None Detected" && hardwareVendor !== "Unknown" ? (
            <>
              {hardwareVendor.includes("Hikvision") && (
                <>
                  <div className="soc-card p-4 space-y-2 border-rose-500/40">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-rose-400">CVE-2021-36260 (CVSS 9.8)</span>
                      <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">CRITICAL</span>
                    </div>
                    <p className="text-xs text-slate-200">Hikvision Web Server Unauthenticated Command Injection Vulnerability</p>
                    <div className="text-[11px] text-[#00F0FF]">Remediation: Update firmware to V5.5.800 or later.</div>
                  </div>
                  <div className="soc-card p-4 space-y-2 border-amber-500/40">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-[#FFB800]">CVE-2017-7921 (CVSS 7.5)</span>
                      <span className="px-2.5 py-0.5 rounded bg-[#FFB800]/20 text-[#FFB800] border border-[#FFB800]/40 text-[10px] font-extrabold">HIGH</span>
                    </div>
                    <p className="text-xs text-slate-200">Hikvision IP Camera Authentication Bypass</p>
                    <div className="text-[11px] text-[#00F0FF]">Remediation: Disable default admin account and update firmware.</div>
                  </div>
                </>
              )}
              {hardwareVendor.includes("Dahua") && (
                <div className="soc-card p-4 space-y-2 border-rose-500/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-400">CVE-2021-33044 (CVSS 9.8)</span>
                    <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">CRITICAL</span>
                  </div>
                  <p className="text-xs text-slate-200">Dahua DVR/NVR Identity Authentication Bypass Vulnerability</p>
                  <div className="text-[11px] text-[#00F0FF]">Remediation: Upgrade Dahua NVR firmware to latest patch.</div>
                </div>
              )}
              {hardwareVendor.includes("Axis") && (
                <div className="soc-card p-4 space-y-2 border-rose-500/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-400">CVE-2018-10660 (CVSS 9.8)</span>
                    <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">CRITICAL</span>
                  </div>
                  <p className="text-xs text-slate-200">Axis Network Camera Authentication Bypass Vulnerability</p>
                  <div className="text-[11px] text-[#00F0FF]">Remediation: Upgrade Axis OS to latest release patch.</div>
                </div>
              )}
              {hardwareVendor.includes("Cisco") && (
                <div className="soc-card p-4 space-y-2 border-rose-500/40">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-rose-400">CVE-2019-15271 (CVSS 9.8)</span>
                    <span className="px-2.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-extrabold">CRITICAL</span>
                  </div>
                  <p className="text-xs text-slate-200">Cisco Video Surveillance Camera Remote Code Execution Vulnerability</p>
                  <div className="text-[11px] text-[#00F0FF]">Remediation: Apply Cisco Security Advisory patch.</div>
                </div>
              )}
            </>
          ) : (
            <div className="soc-card p-4 text-center text-slate-400 text-xs">
              No hardware vendor identified — no vendor-specific CVEs matched
            </div>
          )}

          {/* Credential Flag 1 */}
          <div className="soc-card p-4 flex items-center justify-between border-amber-500/30">
            <div className="space-y-1">
              <div className="text-xs font-bold text-[#FFB800]">Default Credential Awareness Flag</div>
              <div className="text-xs text-slate-300">Default Credential Pair: <code className="text-[#FFB800] bg-[#060913] px-2 py-0.5 rounded">admin : 12345 (Default)</code></div>
            </div>
            <span className="px-2.5 py-1 rounded bg-[#FFB800]/20 text-[#FFB800] border border-[#FFB800]/40 text-[10px] font-extrabold">
              DEFENSIVE ONLY
            </span>
          </div>

          {/* Credential Flag 2 */}
          <div className="soc-card p-4 flex items-center justify-between border-amber-500/30">
            <div className="space-y-1">
              <div className="text-xs font-bold text-[#FFB800]">Default Credential Awareness Flag</div>
              <div className="text-xs text-slate-300">Default Credential Pair: <code className="text-[#FFB800] bg-[#060913] px-2 py-0.5 rounded">admin : admin (Default)</code></div>
            </div>
            <span className="px-2.5 py-1 rounded bg-[#FFB800]/20 text-[#FFB800] border border-[#FFB800]/40 text-[10px] font-extrabold">
              DEFENSIVE ONLY
            </span>
          </div>

        </div>
      </div>

      {/* SURVEILLANCE IP RANGE & VLAN CLUSTER PREDICTIONS */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-[#00F0FF]" />
            <span>SURVEILLANCE IP RANGE & VLAN CLUSTER PREDICTIONS</span>
          </h3>
          <span className="text-[11px] text-[#10B981]">Predictive Subnet Analytics</span>
        </div>

        <div className="space-y-3">
          {/* VLAN 20 */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#FFB800]">VLAN 20 (CCTV & Physical Security)</span>
              <span className="px-2.5 py-0.5 rounded bg-[#10B981]/20 text-[#10B981] border border-[#10B981]/40 text-[10px] font-extrabold">
                98.5% Probability
              </span>
            </div>
            <code className="text-[#00F0FF] bg-[#060913] px-3 py-1 rounded border border-[#1E293B] block font-mono text-xs">
              187.245.231.100 - 187.245.231.150
            </code>
            <div className="text-xs text-slate-400">Likely Devices: Hikvision / Dahua IP Cameras & NVR Recorders</div>
          </div>

          {/* VLAN 30 */}
          <div className="soc-card p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-[#00F0FF]">VLAN 30 (IoT & Building Automation)</span>
              <span className="px-2.5 py-0.5 rounded bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 text-[10px] font-extrabold">
                88.4% Probability
              </span>
            </div>
            <code className="text-[#00F0FF] bg-[#060913] px-3 py-1 rounded border border-[#1E293B] block font-mono text-xs">
              187.245.231.200 - 187.245.231.240
            </code>
            <div className="text-xs text-slate-400">Likely Devices: Smart Switches, BACnet Controllers, Access Control Readers</div>
          </div>
        </div>
      </div>

      {/* AI VISION & BANNER INTERFACE CLASSIFIER */}
      <div className="soc-card p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1E293B] pb-3">
          <h3 className="text-xs font-extrabold text-white uppercase tracking-wider flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-[#A855F7]" />
            <span>AI VISION & BANNER INTERFACE CLASSIFIER</span>
          </h3>
          <span className="text-[11px] text-[#A855F7]">Neural OS Classification</span>
        </div>

        <div className="soc-card p-4 space-y-3 bg-[#060913]">
          <div className="space-y-1">
            <div className="text-slate-400 text-[11px]">Interface Screenshot Classification:</div>
            <div className="text-white font-bold text-xs">CCTV_CAMERA_ADMIN_PANEL</div>
            <div className="text-[#10B981] font-semibold text-xs">Confidence: 97.6% Neural Model Match</div>
          </div>

          <div className="space-y-1 pt-2 border-t border-[#1E293B]">
            <div className="text-slate-400 text-[11px]">Detected Console UI Elements:</div>
            <div className="flex flex-wrap gap-2 pt-1">
              <span className="px-2.5 py-1 bg-cyan-950 text-cyan-300 border border-cyan-800 rounded text-[10px]">Video Stream Canvas</span>
              <span className="px-2.5 py-1 bg-blue-950 text-blue-300 border border-blue-800 rounded text-[10px]">PTZ Joystick Overlay</span>
              <span className="px-2.5 py-1 bg-purple-950 text-purple-300 border border-purple-800 rounded text-[10px]">ONVIF Auth Prompt</span>
            </div>
          </div>
        </div>
      </div>

    </div>
  );
}
