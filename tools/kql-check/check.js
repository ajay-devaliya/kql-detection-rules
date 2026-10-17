// Parses and semantically checks KQL files against the columns these rules use.
// Usage: node tools/kql-check/check.js queries/firewall/*.kql
global.Bridge = require('@kusto/language-service-next/bridge.js');
require('@kusto/language-service-next/Kusto.Language.Bridge.js');
const K = global.Kusto.Language;
const S = K.Symbols;
const fs = require('fs');
const str = S.ScalarTypes.String, int = S.ScalarTypes.Int, long = S.ScalarTypes.Long, dt = S.ScalarTypes.DateTime, dyn = S.ScalarTypes.Dynamic, bool = S.ScalarTypes.Bool, real = S.ScalarTypes.Real;
function col(n,t){ return new S.ColumnSymbol(n,t); }
function tbl(n, cols){ return new S.TableSymbol.$ctor4(n, cols); }
const csl = tbl("CommonSecurityLog", [
 ["TimeGenerated",dt],["DeviceVendor",str],["DeviceProduct",str],["DeviceEventClassID",str],["Activity",str],["DeviceAction",str],
 ["SourceIP",str],["DestinationIP",str],["DestinationPort",int],["SourcePort",int],["Protocol",str],["ApplicationProtocol",str],
 ["DestinationServiceName",str],["DeviceName",str],["DestinationUserName",str],["SourceUserName",str],["AdditionalExtensions",str],
 ["Message",str],["SentBytes",long],["ReceivedBytes",long],["DeviceCustomString1",str],["DeviceCustomString1Label",str],
 ["DeviceCustomString2",str],["DeviceCustomString2Label",str]].map(c=>col(c[0],c[1])));
const ti = tbl("ThreatIntelIndicators", [["TimeGenerated",dt],["Id",str],["ObservableKey",str],["ObservableValue",str],["IsDeleted",bool],["IsActive",bool],["ValidUntil",dt],["Confidence",int],["Data",dyn]].map(c=>col(c[0],c[1])));
const db = new S.DatabaseSymbol.$ctor1("ws", [csl, ti]);
const cl = new S.ClusterSymbol.$ctor1("c", [db]); const globals = K.GlobalState.Default.WithCluster(cl).WithDatabase(db);
let bad = 0;
for (const f of process.argv.slice(2)) {
  const text = fs.readFileSync(f, 'utf8');
  const code = K.KustoCode.ParseAndAnalyze(text, globals);
  const diags = code.GetDiagnostics();
  const n = diags.Count;
  const msgs = [];
  for (let i=0;i<n;i++){ const d = diags.getItem(i); msgs.push(`${d.Severity} @${d.Start}: ${d.Message} [${text.substr(d.Start, 40).replace(/\n/g,' ')}]`); }
  console.log((n? "ISSUES ":"OK     ") + f.split('/').pop() + (n? "\n  " + msgs.join("\n  "):""));
  if (n) bad++;
}
process.exit(bad?1:0);
