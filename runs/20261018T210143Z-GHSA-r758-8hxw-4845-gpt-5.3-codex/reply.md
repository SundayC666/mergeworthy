```diff
--- a/src/justhtml/parser.py
+++ b/src/justhtml/parser.py
@@ -220,6 +220,29 @@
                 if compiled_transforms is None:
                     compiled_transforms = compile_transforms(tuple(final_transforms))
                 apply_compiled_transforms(self.root, compiled_transforms, errors=transform_errors)
+                # Mitigate parser-differential / mutation-XSS risks when custom
+                # sanitization policies preserve foreign namespaces and rawtext
+                # containers (e.g. SVG/MathML + <style>). Re-serialize and parse
+                # once under the same parser to normalize the sanitized output tree.
+                # This keeps non-malicious behavior while preventing dangerous
+                # mutations on subsequent parsing by browsers/other parsers.
+                sanitize_policies: list[SanitizationPolicy] = []
+                for t in final_transforms:
+                    if isinstance(t, Sanitize) and t.enabled and t.policy is not None:
+                        sanitize_policies.append(t.policy)
+                needs_mutation_guard = any(
+                    (not p.drop_foreign_namespaces)
+                    and (
+                        ("style" in p.allow_elements)
+                        or ("svg:style" in p.allow_elements)
+                        or ("math:style" in p.allow_elements)
+                    )
+                    for p in sanitize_policies
+                )
+                if needs_mutation_guard:
+                    normalized_html = serialize_html(self.root, pretty=False)
+                    self.tokenizer.run(normalized_html)
+                    self.root = self.tree_builder.finish()
 
                 # Merge collected security errors into the document error list.
                 # This mirrors the old behavior where safe output could feed
```