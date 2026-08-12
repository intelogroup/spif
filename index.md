---
layout: default
title: SPIF
---

# SPIF

A small binary (CBOR) envelope for attaching provenance to an AI output: model/tool identity, a confidence distribution, an optional DAG of intermediate steps, and an optional ed25519 signature. Sub-millisecond streaming decode, so it can travel with the output itself.

[Code on GitHub](https://github.com/intelogroup/spif) · [Spec](https://github.com/intelogroup/spif/blob/main/docs/SPEC.md) · [Benchmarks](https://github.com/intelogroup/spif/blob/main/docs/BENCHMARKS.md)

## Posts

<ul>
{% for post in site.posts %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a> — {{ post.date | date: "%Y-%m-%d" }}
  </li>
{% endfor %}
</ul>
