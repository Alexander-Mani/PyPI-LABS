Because `deployment.sh` is a fully automated, end-to-end pipeline, it actually does the heavy lifting for you! If you look at the last step of the script (Step 10), it automatically executes your first benchmark run using the `budget` tier of models.

So, once the script finishes successfully on the VM, here is exactly what you should do:

### 1. Retrieve Your First Results
The script will have generated your first set of actual data. The results are stored in the SQLite database owned by the unprivileged runner account.
You can log in as the runner to check them:
```bash
sudo -u pypi-runner -i
cd ~/pypi-scada-repo
sqlite3 src/data/eval_results.db "SELECT run_id, detector, verdict, ground_truth FROM eval_result;"
```
*(You may want to `scp` this `eval_results.db` file off the VM and back to your local machine so you can use DB Browser or Pandas to build the charts for your thesis).*

### 2. Run the Higher-Tier Models
The deployment script intentionally defaults to `--tier budget` to prevent a bug from accidentally draining your OpenAI/Anthropic credits. 

Once you verify that the budget results look structurally correct, you should log back in and run the more expensive, smarter models to get the real data for your "Cost vs. Accuracy" analysis:

```bash
sudo -u pypi-runner -i
cd ~/pypi-scada-repo
source venv/bin/activate

# Run the Medium tier (Claude Sonnet, GPT-5.4-mini, Llama 3)
python src/analyzer/evaluate.py --tier medium

# Run the Frontier tier (Claude Opus, GPT-5.4, Gemini Pro)
python src/analyzer/evaluate.py --tier frontier
```

### 3. Archive Your Evidence
As noted in your `CONCERNS.md` (Risk R-06), you need reproducible artifacts for your university grading. 
After your frontier runs finish, you should archive:
*   The `src/data/eval_results.db` file.
*   The `configs/models.json` file (so you can prove exactly what prices and models were active).
*   The LiteLLM logs (`/home/proxy-runner/litellm.log`) to prove the network proxy isolation worked.

And that's it! Once you have that database file populated with the `budget`, `medium`, and `frontier` runs, your engineering work is essentially done, and you can transition fully to writing the results and conclusion chapters of your BSc thesis.
