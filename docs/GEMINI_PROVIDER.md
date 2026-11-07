# Use Google Gemini API on macOS

Ollama with `gemma4:e4b` is the default. The Gemini route uses Google’s HTTPS Generate Content API and sends the bounded prompt and evidence supplied to the model. [Google Gemini API reference](https://ai.google.dev/api)

## Test with synthetic evidence

1. Create a key in Google AI Studio and verify that the project and exact model have Free tier quota or applicable redeemed credits. Review the project’s data-use terms before enabling real evidence. [Google API key guide](https://ai.google.dev/gemini-api/docs/api-key)
2. In the repository root, create `.env.gemini` with the single line `GEMINI_API_KEY="your-key-here"` and run `chmod 600 .env.gemini`. The file is ignored by Git. You can also export `GEMINI_API_KEY` in the dashboard and monitor environments.
3. Record a short allowance for synthetic testing. Replace both example identities with the model and exact returned version you intend to test. Use `redeemed_credits` only if you have verified applicable credits.

   ```sh
   python3 configure_gemini.py \
     --model gemini-2.5-flash-lite \
     --expected-model-version gemini-2.5-flash-lite \
     --quota-kind free_tier --max-requests 2 --hours 1 \
     --confirm-project-allowance
   ```

4. In **Settings → AI model selection**, select **Gemini API** and enter the same model and version. Click **Test with synthetic evidence only**. A successful check displays the returned version, token counts and advisory report. If the API returns a different model version, verify it and update the local allowance and dashboard pin before testing again.
5. Click **Activate provider/model** to save the route for future requests. Activation and synthetic testing alone do not authorize sending incident evidence.

The local allowance records the operator’s verification and limits generation attempts. Actual quota is set by Google. The app makes no billing changes and has no automatic provider fallback.

## Authorize new incident evidence

Do this only if you have permission to send the lab evidence to Google and the API project is on the Free tier. In the same repository, run the command with the same model and version as the dashboard selection:

```sh
python3 configure_gemini.py \
  --model gemini-2.5-flash-lite \
  --expected-model-version gemini-2.5-flash-lite \
  --quota-kind free_tier --confirm-project-allowance --ongoing-live
```

This creates the ignored `.gemini-live-access.local.json` authorization bound to the key, model, version and start time. Gemini can then receive new SSH advisory incidents that start after authorization. Saved incident comparisons run with Ollama. To revoke future Gemini uploads, switch back to Ollama and remove the local live authorization file. A request already sent may complete.
