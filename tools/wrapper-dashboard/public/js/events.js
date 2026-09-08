export function connectEvents({ refresh, loadEditor, isEditorDirty }) {
  const events = new EventSource("/api/events");
  events.onmessage = () => {
    refresh();
    if (!isEditorDirty()) loadEditor();
  };
  return events;
}
