export function TermsPage() {
  return (
    <article className="max-w-3xl space-y-5 text-slate-300">
      <h1 className="text-3xl font-semibold text-white">Terms of use</h1>
      <p className="text-sm text-slate-500">Informal acceptable-use notes for this software. Not a legal contract.</p>
      <ul className="list-disc space-y-2 pl-5">
        <li>Use LinkShield to investigate URLs you received or that you are authorized to examine.</li>
        <li>Do not use the scanner to attack, flood, or probe systems you do not operate.</li>
        <li>Do not rely on a low-risk label as permission to click a link or to ignore other warnings.</li>
        <li>Respect Google Safe Browsing, VirusTotal, and RDAP terms, quotas, and attribution requirements.</li>
        <li>The authors provide the software as-is, without warranties of merchantability, fitness, or accuracy.</li>
        <li>Reports may be incomplete, incorrect, or outdated. You remain responsible for your own decisions.</li>
      </ul>
    </article>
  );
}
