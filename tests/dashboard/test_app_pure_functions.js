/*
 * test_app_pure_functions.js
 * =============================
 * app.js'deki SAF fonksiyonlari (DOM/fetch'e bagimli olmayanlari)
 * dogrudan Node.js altinda test eder. Bu, ADR 0011'deki "framework I/O
 * ile saf mantigin ayrilmasi" priniibinin frontend'deki karsiligi --
 * bu sayede dashboard mantiginin bir kismi gercekten, bu sandbox'ta,
 * bir tarayici olmadan test edilebiliyor.
 *
 * Calistirmak icin: node tests/dashboard/test_app_pure_functions.js
 */

const path = require("path");
const { riskColor, buildGraphData, formatConfidence, sortRiskScoresDescending } = require(
  path.join(__dirname, "..", "..", "src", "sentinelpath", "static", "dashboard", "app.js")
);

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed += 1;
  } else {
    failed += 1;
    console.log(`FAIL: ${message}`);
  }
}

// --- riskColor ---
assert(riskColor(80) === "#ff6666", "riskColor(80) kirmizi olmali");
assert(riskColor(45) === "#ffe766", "riskColor(45) sari olmali");
assert(riskColor(10) === "#8ec843", "riskColor(10) yesil olmali");
assert(riskColor(60) === "#ff6666", "riskColor(60) sinir degeri kirmizi olmali (>=60)");
assert(riskColor(30) === "#ffe766", "riskColor(30) sinir degeri sari olmali (>=30)");

// --- formatConfidence ---
assert(formatConfidence(0.5) === "0.50", "formatConfidence(0.5) '0.50' olmali");
assert(formatConfidence(null) === "N/A", "formatConfidence(null) 'N/A' olmali (bkz. ADR 0010)");
assert(formatConfidence(undefined) === "N/A", "formatConfidence(undefined) 'N/A' olmali");
assert(formatConfidence(0) === "0.00", "formatConfidence(0) '0.00' olmali (0 ile null KARISTIRILMAMALI)");

// --- sortRiskScoresDescending ---
const unsorted = [{ score: 10 }, { score: 90 }, { score: 50 }];
const sorted = sortRiskScoresDescending(unsorted);
assert(sorted[0].score === 90 && sorted[1].score === 50 && sorted[2].score === 10, "sortRiskScoresDescending azalan sirada olmali");
assert(unsorted[0].score === 10, "sortRiskScoresDescending orijinal diziyi DEGISTIRMEMELI (yeni dizi donmeli)");

// --- buildGraphData ---
const sampleReport = {
  target_node: "host-a",
  risk_scores: [
    { target_node: "host-b", technique_id: "T1021.001", probability: 0.75, score: 53.4 },
    { target_node: "host-c", technique_id: "T1078", probability: 0.25, score: 15.8 },
  ],
};
const graph = buildGraphData(sampleReport);
assert(graph.nodes.length === 3, "buildGraphData 3 node uretmeli (host-a, host-b, host-c)");
assert(graph.edges.length === 2, "buildGraphData 2 edge uretmeli");
assert(graph.edges[0].from === "host-a" && graph.edges[0].to === "host-b", "ilk edge host-a -> host-b olmali");
assert(graph.edges[0].label.includes("T1021.001"), "edge etiketi teknik ID icermeli");
assert(graph.edges[0].label.includes("75"), "edge etiketi olasilik yuzdesini icermeli");

const sourceNode = graph.nodes.find((n) => n.id === "host-a");
assert(sourceNode.color === "#ff9d4d", "kaynak node farkli renkte (turuncu) olmali");

const destNode = graph.nodes.find((n) => n.id === "host-b");
assert(destNode.color === "#4fa3ff", "hedef node'lar mavi olmali");

// Bos risk_scores durumu (izole start_node -- bkz. orchestrator testi)
const emptyReport = { target_node: "host-x", risk_scores: [] };
const emptyGraph = buildGraphData(emptyReport);
assert(emptyGraph.nodes.length === 1, "bos risk_scores ile bile kaynak node grafta olmali");
assert(emptyGraph.edges.length === 0, "bos risk_scores ile hic edge olmamali");

console.log(`--- ${passed} passed, ${failed} failed ---`);
process.exit(failed > 0 ? 1 : 0);
