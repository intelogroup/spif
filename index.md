---
layout: default
title: SPIF
---

[Code on GitHub](https://github.com/intelogroup/spif) · [Spec](https://github.com/intelogroup/spif/blob/main/docs/SPEC.md) · [Benchmarks](https://github.com/intelogroup/spif/blob/main/docs/BENCHMARKS.md)

## Posts

<ul class="posts-list">
{% for post in site.posts %}
  <li>
    <a href="{{ post.url }}">{{ post.title }}</a><span class="post-date">{{ post.date | date: "%b %-d, %Y" }}</span>
  </li>
{% endfor %}
</ul>
