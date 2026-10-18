# system

You are a security engineer fixing a reported vulnerability in a Python library. You will receive the public advisory and the exact function or class it concerns. Fix the vulnerability in that code. Do not weaken, skip or delete tests. Keep existing behaviour for non-malicious input.

# user

## Advisory

# justhtml: Mutation XSS with custom foreign-namespace sanitization policies

## Summary
A parser-differential / mutation XSS issue was found in justhtml when using a custom sanitization policy that preserves foreign namespaces such as SVG or MathML.

Under these custom settings, specially crafted input could sanitize into HTML that looked safe at first, but became unsafe when parsed again by a browser or another HTML parser.

## Impact
This issue does not affect the default safe configuration.

You may be affected if you use a custom SanitizationPolicy with settings like:

```
drop_foreign_namespaces=False
allowlisted foreign elements such as MathML or SVG
allowlisted raw-text containers such as <style>
In that case, an attacker could inject markup that survives sanitization and turns into active HTML after re-parsing.
```

## Workarounds
Until you upgrade:

```
keep drop_foreign_namespaces=True
avoid allowlisting foreign namespaces for untrusted input
avoid allowlisting raw-text containers such as <style> in custom policies
```

## Notes
The default `JustHTML(..., sanitize=True)` behavior was not found to be vulnerable in this issue.


# Task
Fix the vulnerability directly in the library source code.

## Location

File: `src/justhtml/parser.py`
Target: `JustHTML.__init__`
The code below is lines 57-263 of that file, shown exactly as in the repository.

## Current code

```python
    def __init__(
        self,
        html: str | bytes | bytearray | memoryview | Node | Text | None,
        *,
        sanitize: bool | None = None,
        safe: bool | None = None,
        policy: SanitizationPolicy | None = None,
        collect_errors: bool = False,
        track_node_locations: bool = False,
        debug: bool = False,
        encoding: str | None = None,
        fragment: bool = False,
        fragment_context: FragmentContext | None = None,
        iframe_srcdoc: bool = False,
        scripting_enabled: bool = True,
        strict: bool = False,
        tokenizer_opts: TokenizerOpts | None = None,
        tree_builder: TreeBuilder | None = None,
        transforms: list[TransformSpec] | None = None,
    ) -> None:
        # `sanitize` is the primary API (preferred). `safe` is kept as a
        # backwards-compatible alias.
        if sanitize is None and safe is None:
            sanitize_enabled = True
        elif sanitize is None and safe is not None:
            sanitize_enabled = bool(safe)
        elif sanitize is not None and safe is None:
            sanitize_enabled = bool(sanitize)
        else:
            sanitize_enabled = bool(sanitize)
            if sanitize_enabled != bool(safe):
                raise ValueError("Conflicting values for sanitize and safe; use only sanitize=")

        if fragment_context is not None:
            fragment = True

        if fragment and fragment_context is None:
            fragment_context = FragmentContext("div")

        track_tag_spans = False
        has_sanitize_transform = False
        explicit_sanitize_policy: SanitizationPolicy | None = None
        needs_escape_incomplete_tags = False
        if transforms:
            from .sanitize import DEFAULT_POLICY  # noqa: PLC0415
            from .transforms import Sanitize  # noqa: PLC0415

            for t in transforms:
                if isinstance(t, Sanitize):
                    has_sanitize_transform = True
                    if explicit_sanitize_policy is None:
                        explicit_sanitize_policy = t.policy
                    effective = t.policy or DEFAULT_POLICY
                    if effective.disallowed_tag_handling == "escape":
                        track_tag_spans = True
                        needs_escape_incomplete_tags = True
                        break

        # If we will auto-sanitize (sanitize=True and no Sanitize in transforms),
        # escape-mode tag reconstruction may require tracking tag spans.
        if sanitize_enabled and not has_sanitize_transform and policy is not None:
            if policy.disallowed_tag_handling == "escape":
                track_tag_spans = True
                needs_escape_incomplete_tags = True

        self.debug = bool(debug)
        self.fragment_context = fragment_context
        self.encoding = None

        html_str: str
        if isinstance(html, (Node, Text)):
            html_for_serialization = html
            if sanitize_enabled or has_sanitize_transform:
                from .sanitize import (  # noqa: PLC0415
                    DEFAULT_DOCUMENT_POLICY,
                    DEFAULT_POLICY,
                    _sanitize_rawtext_element_contents,
                )

                html_for_serialization = html.clone_node(deep=True)
                effective_policy = explicit_sanitize_policy or policy
                if effective_policy is None:
                    effective_policy = (
                        DEFAULT_DOCUMENT_POLICY if html_for_serialization.name == "#document" else DEFAULT_POLICY
                    )
                _sanitize_rawtext_element_contents(html_for_serialization, policy=effective_policy, errors=None)
            html_str = serialize_html(html_for_serialization, pretty=False)
        elif isinstance(html, (bytes, bytearray, memoryview)):
            html_str, chosen = decode_html(bytes(html), transport_encoding=encoding)
            self.encoding = chosen
        elif html is not None:
            html_str = str(html)
        else:
            html_str = ""

        # Enable error collection if strict mode is on.
        # Node location tracking is opt-in to avoid slowing down the common case.
        should_collect = collect_errors or strict

        self.tree_builder = tree_builder or TreeBuilder(
            fragment_context=fragment_context,
            iframe_srcdoc=iframe_srcdoc,
            collect_errors=should_collect,
            scripting_enabled=scripting_enabled,
            track_tag_spans=track_tag_spans,
        )
        opts = tokenizer_opts.copy() if tokenizer_opts is not None else TokenizerOpts()
        opts.scripting_enabled = bool(scripting_enabled)
        if needs_escape_incomplete_tags:
            opts.emit_bogus_markup_as_text = True

        # For RAWTEXT fragment contexts, set initial tokenizer state and rawtext tag
        if fragment_context and not fragment_context.namespace:
            rawtext_elements = {"textarea", "title", "style"}
            tag_name = fragment_context.tag_name.lower()
            if tag_name in rawtext_elements:
                opts.initial_state = Tokenizer.RAWTEXT
                opts.initial_rawtext_tag = tag_name
            elif tag_name in ("plaintext", "script"):
                opts.initial_state = Tokenizer.PLAINTEXT

        self.tokenizer = Tokenizer(
            self.tree_builder,
            opts,
            collect_errors=should_collect,
            track_node_locations=bool(track_node_locations),
            track_tag_positions=bool(track_node_locations) or track_tag_spans,
        )
        # Link tokenizer to tree_builder for position info
        self.tree_builder.tokenizer = self.tokenizer

        self.tokenizer.run(html_str)
        self.root = self.tree_builder.finish()

        transform_errors: list[ParseError] = []

        # Apply transforms after parse.
        # Safety model: when sanitize=True, the in-memory tree is sanitized exactly once
        # during construction by ensuring a Sanitize transform runs. If the user
        # places an explicit Sanitize() in the transform list, that explicit
        # position becomes the sanitize point (no extra final pass is appended).
        if transforms or sanitize_enabled:
            from .sanitize import DEFAULT_DOCUMENT_POLICY, DEFAULT_POLICY  # noqa: PLC0415
            from .transforms import Sanitize  # noqa: PLC0415

            final_transforms: list[TransformSpec] = list(transforms or [])

            # Normalize explicit Sanitize() transforms to use the same default policy
            # choice as the old safe-output sanitizer (document vs fragment).
            if final_transforms:
                default_mode_policy = DEFAULT_DOCUMENT_POLICY if self.root.name == "#document" else DEFAULT_POLICY
                for i, t in enumerate(final_transforms):
                    if isinstance(t, Sanitize) and t.policy is None:
                        final_transforms[i] = Sanitize(
                            policy=default_mode_policy, enabled=t.enabled, callback=t.callback, report=t.report
                        )

            # Auto-append a final Sanitize step only if the user didn't include
            # Sanitize anywhere in their transform list.
            if sanitize_enabled and not has_sanitize_transform:
                effective_policy = (
                    policy
                    if policy is not None
                    else (DEFAULT_DOCUMENT_POLICY if self.root.name == "#document" else DEFAULT_POLICY)
                )
                # Avoid stale collected errors on reused policy objects.
                if effective_policy.unsafe_handling == "collect":
                    effective_policy.reset_collected_security_errors()
                final_transforms.append(Sanitize(policy=effective_policy))

            if final_transforms:
                compiled_transforms = None
                if len(final_transforms) == 1 and isinstance(final_transforms[0], Sanitize):
                    only = final_transforms[0]
                    p = only.policy
                    if only.enabled and only.callback is None and only.report is None and p is not None:
                        compiled_transforms = p._compiled_sanitize_transforms
                        if compiled_transforms is None:
                            compiled_transforms = compile_transforms((only,))
                            object.__setattr__(p, "_compiled_sanitize_transforms", compiled_transforms)

                if compiled_transforms is None:
                    compiled_transforms = compile_transforms(tuple(final_transforms))
                apply_compiled_transforms(self.root, compiled_transforms, errors=transform_errors)

                # Merge collected security errors into the document error list.
                # This mirrors the old behavior where safe output could feed
                # security findings into doc.errors.
                for t in final_transforms:
                    if isinstance(t, Sanitize):
                        t_policy = t.policy
                        if t_policy is not None and t_policy.unsafe_handling == "collect":
                            if t_policy.collects_security_errors_into(transform_errors):
                                continue
                            transform_errors.extend(t_policy.collected_security_errors())

        if should_collect:
            # Merge errors from both tokenizer and tree builder.
            # Public API: users expect errors to be ordered by input position.
            merged_errors = self.tokenizer.errors + self.tree_builder.errors + transform_errors
            self.errors = self._sorted_errors(merged_errors)
        else:
            self.errors = transform_errors

        # In strict mode, raise on first error
        if strict and self.errors:
            raise StrictModeError(self.errors[0])
```

## Output

Reply with ONE unified diff and nothing else, inside a ```diff code fence. Paths are relative to the repository root with the usual a/ and b/ prefixes (for example `--- a/src/justhtml/parser.py` / `+++ b/src/justhtml/parser.py`). Every hunk header must carry real line numbers, like `@@ -376,4 +376,6 @@`. Context lines must match the file exactly. The diff must apply cleanly with `git apply` from the repository root. Do not add explanations before or after it.