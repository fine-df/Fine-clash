# Fine-clash

Automatic Clash subscription generator.

Current architecture:

- clash_monitor.py: subscription collection and configuration generation
- node_parser.py: node parsing
- node_health.py: node availability checking
- subscription_sources.json: subscription source pool
- GitHub Actions: scheduled generation

Pipeline:

subscription sources -> parser -> health check -> live_clash.yaml
