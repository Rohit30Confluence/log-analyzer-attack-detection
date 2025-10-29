import Link from "next/link";

export default function Docs() {
  return (
    <main className="min-h-screen bg-white text-gray-800">
      <div className="max-w-4xl mx-auto py-16 px-6">
        <h1 className="text-4xl font-bold mb-6">Documentation</h1>
        <p className="mb-4">
          This tool analyzes Apache access logs to detect security threats such as
          brute-force, SQL injection, and XSS attacks using both rule-based and
          anomaly-based detection engines.
        </p>
        <h2 className="text-2xl font-semibold mt-8 mb-3">Getting Started</h2>
        <pre className="bg-gray-100 p-4 rounded text-sm overflow-x-auto">
{`git clone https://github.com/Rohit30Confluence/log-analyzer-attack-detection.git
cd log-analyzer-attack-detection
pip install -r requirements.txt
python cli/main.py --log path/to/access.log --visualize`}
        </pre>

        <h2 className="text-2xl font-semibold mt-8 mb-3">Visualization</h2>
        <p>
          Run <code>scripts/visualize_results.py</code> to generate attack trend
          graphs and IP activity charts using Matplotlib.
        </p>

        <div className="mt-10">
          <Link href="/" className="text-blue-600 hover:underline">
            ← Back to Home
          </Link>
        </div>
      </div>
    </main>
  );
}
