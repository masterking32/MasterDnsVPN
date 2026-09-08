export const dashboardState = {
  state: null,
  resolverOffset: 0,
  resolverFilter: "",
  editorDirty: false
};

export function setState(nextState) {
  dashboardState.state = nextState;
}

export function setResolverFilter(value) {
  dashboardState.resolverFilter = value;
  dashboardState.resolverOffset = 0;
}

export function setEditorDirty(value) {
  dashboardState.editorDirty = value;
}
