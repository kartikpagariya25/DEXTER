import React from "react";

// GreenLeaf Bank -- transaction note preview (demo, deliberately vulnerable)
export function TransactionNote({ note }) {
  // Gap: renders user-supplied transaction note as raw HTML.
  return <div dangerouslySetInnerHTML={{ __html: note }} />;
}
