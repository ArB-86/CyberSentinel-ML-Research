import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

if os.getenv("GEMINI_API_KEY") and not os.getenv("GOOGLE_API_KEY"):
    os.environ["GOOGLE_API_KEY"] = os.getenv("GEMINI_API_KEY")

from agent.agent import run_investigation
from agent.workflow import generate_report_from_json

selected_event_id = "EVT-00002"
selected_target_ip = "192.168.10.50"

print("==================================================")
print(f"Starting Investigation for Event ID: {selected_event_id}")
print("==================================================\n")

# Step 1: Output directory setup
output_dir = Path("outputs/agentic_investigation_output")
output_dir.mkdir(parents=True, exist_ok=True)

# Step 2: Investigation run
result = run_investigation(
    event_id=selected_event_id,
    target_ip=selected_target_ip
)

print("\n--- Investigation Completed ---")

final_messages = result.get("messages", [])
if final_messages:
    raw_content = final_messages[-1].content
    if isinstance(raw_content, list):
        investigation_json_str = "".join([str(item) for item in raw_content])
    else:
        investigation_json_str = str(raw_content)

    # 1. JSON file save kar rahe hain
    json_file_path = output_dir / f"investigation_{selected_event_id}.json"
    with open(json_file_path, "w", encoding="utf-8") as f:
        f.write(investigation_json_str)
    print(f"✅ Raw Investigation JSON saved to: {json_file_path}")

    # 2. Markdown Report generate karke save kar rahe hain
    print("⏳ Generating Professional Markdown Report...")
    markdown_report = generate_report_from_json(investigation_json_str)

    md_file_path = output_dir / f"report_{selected_event_id}.md"
    with open(md_file_path, "w", encoding="utf-8") as f:
        f.write(markdown_report)
    print(f"✅ Professional SOC Report saved to: {md_file_path}")

print("\n🎉 Output files successfully generated in folder!")