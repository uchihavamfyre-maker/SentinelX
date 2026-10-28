"""Command-line interface for generating, analyzing, and evaluating data."""
import argparse, json
from pathlib import Path
from pydantic import ValidationError
from .detection import detect_brute_force
from .evaluation import evaluate_detector
from .models import AuthEvent
from .synthetic import generate_events

def read_events(path: str) -> list[AuthEvent]:
    events = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip(): continue
            try: events.append(AuthEvent.model_validate_json(line))
            except ValidationError as exc: raise ValueError(f"Invalid event on line {line_number}: {exc}") from exc
    return events

def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinelx")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate"); gen.add_argument("--out", default="data/sample_events.jsonl"); gen.add_argument("--seed", type=int, default=7)
    analyze = sub.add_parser("analyze"); analyze.add_argument("--input", required=True); analyze.add_argument("--out", default="reports/alerts.json"); analyze.add_argument("--threshold", type=int, default=5); analyze.add_argument("--window-seconds", type=int, default=300)
    evaluate = sub.add_parser("evaluate"); evaluate.add_argument("--input", required=True); evaluate.add_argument("--threshold", type=int, default=5); evaluate.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args()
    if args.command == "generate":
        events = generate_events(args.seed); target = Path(args.out); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("".join(event.model_dump_json() + "\n" for event in events), encoding="utf-8")
        print(f"Wrote {len(events)} synthetic events to {target}")
    elif args.command == "analyze":
        events = read_events(args.input); alerts = detect_brute_force(events, args.threshold, args.window_seconds)
        target = Path(args.out); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps([a.model_dump(mode="json") for a in alerts], indent=2) + "\n", encoding="utf-8")
        print(f"Analyzed {len(events)} events; produced {len(alerts)} alerts; report: {target}")
    else:
        print(evaluate_detector(read_events(args.input), args.threshold, args.window_seconds).model_dump_json(indent=2))

if __name__ == "__main__": main()
