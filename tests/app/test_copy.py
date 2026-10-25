"""Keep the demo copy direct without removing its security/licence warning."""
from html.parser import HTMLParser
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class PageCopyTests(unittest.TestCase):
    def test_clear_headings_warning_and_no_repeated_ornamental_copy(self):
        page=(ROOT/'src/python/cr01_sc/web/index.html').read_text(encoding='utf-8')
        script=(ROOT/'src/python/cr01_sc/web/app.js').read_text(encoding='utf-8')
        class Text(HTMLParser):
            def __init__(self): super().__init__();self.parts=[]
            def handle_data(self,data): self.parts.append(data)
        parsed=Text();parsed.feed(page);visible=' '.join(parsed.parts)
        for heading in ('Session protocol demo','Protocol overview','Test results',
                        'Startup and session timings','Algorithms and key sizes','Security limits'):
            self.assertIn(heading,visible)
        for warning in ('not production-ready','No independent audit, quantum-security proof or side-channel assurance.',
                        'PolyForm Noncommercial 1.0.0 · no commercial use'):
            self.assertIn(warning,visible)
        for phrase in ('Security should be visible','Claims remain attached','The channel is quiet',
                       'THE HONEST BASELINE','Preparation is not free','Validation runway',
                       'mythologized','Return to signal','Recorded runs are not live benchmarks'):
            self.assertNotIn(phrase,visible)
        for repeated in ('family.boundary','lifecycle.boundary','result.summary.claim_boundary'):
            self.assertNotIn(repeated,script)
        self.assertIn('unavailable ? "Report unavailable"',script)
        for name in ('README.md','docs/GUIDE.md','docs/RESULTS.md','docs/PROTOCOL.md','docs/VALIDATION.md','reports/README.md'):
            text=(ROOT/name).read_text(encoding='utf-8')
            with self.subTest(document=name):
                self.assertNotRegex(text,r'\b0\.(?:14|15)\.0\b')
                self.assertNotRegex(text,r'(?i)\b(?:the final review|this edition|this patch|slower observation|prior binary result)\b')
        results=(ROOT/'docs/RESULTS.md').read_text(encoding='utf-8')
        for value in ('5.848','0.724','3.070','38.637','8.568','6.168','0.765','3.877'):
            self.assertIn(value,results)
        transport=json.loads((ROOT/'reports/benchmarks/transport.json').read_text(encoding='utf-8'))
        large=next(row for row in transport['comparison'] if row['payload_bytes']==1048576)
        for field in ('binary_ms','json_ms'):
            self.assertIn(f"{large[field]:.3f}",results)
