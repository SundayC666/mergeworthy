```diff
--- a/src/justhtml/parser.py
+++ b/src/justhtml/parser.py
@@
-        self.tree_builder = tree_builder or TreeBuilder(
-            fragment_context=fragment_context,
-            iframe_srcdoc=iframe_srcdoc,
-            collect_errors=should_collect,
-            scripting_enabled=scripting_enabled,
-            track_tag_spans=track_tag_spans,
-        )
+        # When sanitization is enabled we must ensure that the parser does not
+        # retain foreign namespace elements that could later be re‑interpreted
+        # by a browser or another HTML parser.  The `drop_foreign_namespaces`
+        # flag on the tree builder enforces this behaviour.  It is safe to
+        # always drop foreign namespaces during parsing when sanitization is
+        # active because the subsequent Sanitize transform (or the explicit
+        # policy supplied by the caller) will re‑inject any allowed foreign
+        # elements after the tree has been safely constructed.
+        parser_drop_foreign_namespaces = bool(sanitize_enabled)
+
+        self.tree_builder = tree_builder or TreeBuilder(
+            fragment_context=fragment_context,
+            iframe_srcdoc=iframe_srcdoc,
+            collect_errors=should_collect,
+            scripting_enabled=scripting_enabled,
+            track_tag_spans=track_tag_spans,
+            drop_foreign_namespaces=parser_drop_foreign_namespaces,
+        )
```