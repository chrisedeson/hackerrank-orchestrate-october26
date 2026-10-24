# Runtime usage report

The final run is deterministic and makes **zero LLM/provider API calls**: API input/output tokens are 0 and API cost is $0. Local OCR is nevertheless runtime model work, not a provider API call.

| Runtime component | Calls | Model/tool | Token metering | API cost |
|---|---:|---|---|---:|
| LLM/provider APIs | 0 | none | 0 input / 0 output | $0 |
| Image OCR | 11 | Tesseract 5.3.4, `eng` LSTM | not applicable | $0 API cost |
| PDF text extraction | 4 | Poppler text layer tools | not applicable | $0 API cost |

A fresh full media extraction produced zero warnings and approximately 16k extracted media characters. Local compute/infrastructure cost is excluded rather than priced. The verified fresh final run processed 518 requests in 20.869 seconds and produced output SHA-256 `305a9cbaf551be1b85bb7ee41b57052f9ea1d59869ee671ec66d886559c419c4`. Final metrics are recorded in `evaluation_report.md`; this report makes no accuracy claim.

## Final-run totals

| Measure | Total | Average per request |
|---|---:|---:|
| LLM input tokens | 0 | 0 |
| LLM output tokens | 0 | 0 |
| LLM total tokens | 0 | 0 |
| Provider/API cost | $0 | $0 |
| Local OCR inferences | 11 | 0.021236 |
| PDF text reads | 4 | not applicable |

PDF text reads are extraction operations, not models; OCR is local non-token inference. No additional LLM model provider is used. Infrastructure costs and development-assistant costs are excluded, not asserted to be zero.
