"""Manual end-to-end investigation smoke test.

Run explicitly with `python test_agent.py` after configuring a model provider
and generating the required event/graph outputs. Importing this module is safe
and does not invoke an external LLM during test discovery.
"""
import json
import os
from pathlib import Path

from dotenv import load_dotenv


def main() -> None:
    load_dotenv()
    if os.getenv("GEMINI_API_KEY") and not os.getenv("GOOGLE_API_KEY"):
        os.environ["GOOGLE_API_KEY"] = os.getenv("GEMINI_API_KEY")

    from agent.agent import run_investigation
    from agent.workflow import generate_report_from_json

    event_id = os.getenv("CYBERSENTINEL_TEST_EVENT_ID", "EVT-00002")
    output_dir = Path("outputs/agentic_investigation_output")
    output_dir.mkdir(parents=True, exist_ok=True)

    result = run_investigation(event_id=event_id)
    final_messages = result.get("messages", [])
    if not final_messages:
        raise RuntimeError("Investigation returned no final message.")

    raw = final_messages[-1].content
    if isinstance(raw, list):
        raw = "".join(
            str(item.get("text", item)) if isinstance(item, dict) else str(item)
            for item in raw
        )
    payload = json.loads(str(raw))
    report = generate_report_from_json(json.dumps(payload, ensure_ascii=False))

    (output_dir / f"investigation_{event_id}.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / f"report_{event_id}.md").write_text(report, encoding="utf-8")
    print(f"Investigation artefacts written to {output_dir}")


if __name__ == "__main__":
    main()
