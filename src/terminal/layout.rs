// ╔══════════════════════════════════════════════════════════════════╗
// ║              GhostShell — Layout Engine                          ║
// ║         Binary tree splits, tabs, dynamic resize                 ║
// ╚══════════════════════════════════════════════════════════════════╝

use uuid::Uuid;

/// Split direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitDirection {
    Horizontal,
    Vertical,
}

/// A node in the layout binary tree
#[derive(Debug, Clone)]
pub enum LayoutNode {
    /// A leaf node containing a pane
    Pane {
        id: Uuid,
    },
    /// A split containing two children
    Split {
        direction: SplitDirection,
        ratio: f32,       // 0.0 - 1.0, position of the split
        first: Box<LayoutNode>,
        second: Box<LayoutNode>,
    },
}

/// A tab workspace containing a layout tree
#[derive(Debug, Clone)]
pub struct Tab {
    pub name: String,
    pub root: LayoutNode,
    pub id: Uuid,
}

/// The layout engine manages tabs and the split tree within each tab
pub struct LayoutEngine {
    pub tabs: Vec<Tab>,
    pub active_tab: usize,
    pub active_pane_id: Option<Uuid>,
    next_tab_num: usize,
}

impl LayoutEngine {
    pub fn new() -> Self {
        let initial_id = Uuid::new_v4();
        let initial_tab = Tab {
            name: "main".to_string(),
            root: LayoutNode::Pane { id: initial_id },
            id: Uuid::new_v4(),
        };

        Self {
            tabs: vec![initial_tab],
            active_tab: 0,
            active_pane_id: Some(initial_id),
            next_tab_num: 1,
        }
    }

    /// Get the currently active pane ID
    pub fn active_pane_id(&self) -> Option<Uuid> {
        self.active_pane_id
    }

    /// Split the active pane horizontally
    pub fn split_horizontal(&mut self) {
        self.split(SplitDirection::Horizontal);
    }

    /// Split the active pane vertically
    pub fn split_vertical(&mut self) {
        self.split(SplitDirection::Vertical);
    }

    fn split(&mut self, direction: SplitDirection) {
        if let Some(active_id) = self.active_pane_id {
            let new_id = Uuid::new_v4();
            if let Some(tab) = self.tabs.get_mut(self.active_tab) {
                tab.root = Self::split_node(tab.root.clone(), active_id, new_id, direction);
            }
            self.active_pane_id = Some(new_id);
        }
    }

    fn split_node(
        node: LayoutNode,
        target_id: Uuid,
        new_id: Uuid,
        direction: SplitDirection,
    ) -> LayoutNode {
        match node {
            LayoutNode::Pane { id } if id == target_id => {
                LayoutNode::Split {
                    direction,
                    ratio: 0.5,
                    first: Box::new(LayoutNode::Pane { id }),
                    second: Box::new(LayoutNode::Pane { id: new_id }),
                }
            }
            LayoutNode::Split {
                direction: d,
                ratio,
                first,
                second,
            } => LayoutNode::Split {
                direction: d,
                ratio,
                first: Box::new(Self::split_node(*first, target_id, new_id, direction)),
                second: Box::new(Self::split_node(*second, target_id, new_id, direction)),
            },
            other => other,
        }
    }

    /// Remove a pane from the layout
    pub fn remove_pane(&mut self, pane_id: Uuid) {
        if let Some(tab) = self.tabs.get_mut(self.active_tab) {
            if let Some(new_root) = Self::remove_node(&tab.root, pane_id) {
                tab.root = new_root;
            }
        }

        // Find a new active pane
        if self.active_pane_id == Some(pane_id) {
            self.active_pane_id = self.collect_pane_ids().into_iter().next();
        }
    }

    fn remove_node(node: &LayoutNode, target_id: Uuid) -> Option<LayoutNode> {
        match node {
            LayoutNode::Pane { id } if *id == target_id => None,
            LayoutNode::Pane { .. } => Some(node.clone()),
            LayoutNode::Split {
                first, second, ..
            } => {
                let new_first = Self::remove_node(first, target_id);
                let new_second = Self::remove_node(second, target_id);

                match (new_first, new_second) {
                    (Some(f), Some(s)) => Some(LayoutNode::Split {
                        direction: match node {
                            LayoutNode::Split { direction, .. } => *direction,
                            _ => SplitDirection::Horizontal,
                        },
                        ratio: match node {
                            LayoutNode::Split { ratio, .. } => *ratio,
                            _ => 0.5,
                        },
                        first: Box::new(f),
                        second: Box::new(s),
                    }),
                    (Some(remaining), None) | (None, Some(remaining)) => Some(remaining),
                    (None, None) => None,
                }
            }
        }
    }

    /// Collect all pane IDs in the current tab
    pub fn collect_pane_ids(&self) -> Vec<Uuid> {
        let mut ids = Vec::new();
        if let Some(tab) = self.tabs.get(self.active_tab) {
            Self::collect_ids(&tab.root, &mut ids);
        }
        ids
    }

    fn collect_ids(node: &LayoutNode, ids: &mut Vec<Uuid>) {
        match node {
            LayoutNode::Pane { id } => ids.push(*id),
            LayoutNode::Split { first, second, .. } => {
                Self::collect_ids(first, ids);
                Self::collect_ids(second, ids);
            }
        }
    }

    /// Navigate focus
    pub fn focus_up(&mut self) {
        self.cycle_focus(-1);
    }

    pub fn focus_down(&mut self) {
        self.cycle_focus(1);
    }

    pub fn focus_left(&mut self) {
        self.cycle_focus(-1);
    }

    pub fn focus_right(&mut self) {
        self.cycle_focus(1);
    }

    fn cycle_focus(&mut self, delta: i32) {
        let ids = self.collect_pane_ids();
        if ids.is_empty() {
            return;
        }

        let current_idx = self
            .active_pane_id
            .and_then(|id| ids.iter().position(|&i| i == id))
            .unwrap_or(0);

        let new_idx = if delta > 0 {
            (current_idx + 1) % ids.len()
        } else {
            if current_idx == 0 {
                ids.len() - 1
            } else {
                current_idx - 1
            }
        };

        self.active_pane_id = Some(ids[new_idx]);
    }

    /// Create a new tab
    pub fn new_tab(&mut self) {
        let id = Uuid::new_v4();
        let pane_id = Uuid::new_v4();
        self.tabs.push(Tab {
            name: format!("tab-{}", self.next_tab_num),
            root: LayoutNode::Pane { id: pane_id },
            id,
        });
        self.next_tab_num += 1;
        self.active_tab = self.tabs.len() - 1;
        self.active_pane_id = Some(pane_id);
    }

    /// Switch to next tab
    pub fn next_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.active_tab = (self.active_tab + 1) % self.tabs.len();
            self.active_pane_id = self.collect_pane_ids().into_iter().next();
        }
    }

    /// Switch to previous tab
    pub fn prev_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.active_tab = if self.active_tab == 0 {
                self.tabs.len() - 1
            } else {
                self.active_tab - 1
            };
            self.active_pane_id = self.collect_pane_ids().into_iter().next();
        }
    }

    /// Calculate layout rectangles for rendering
    pub fn calculate_rects(
        &self,
        area: ratatui::layout::Rect,
    ) -> Vec<(Uuid, ratatui::layout::Rect)> {
        let mut result = Vec::new();
        if let Some(tab) = self.tabs.get(self.active_tab) {
            Self::calc_node_rects(&tab.root, area, &mut result);
        }
        result
    }

    fn calc_node_rects(
        node: &LayoutNode,
        area: ratatui::layout::Rect,
        result: &mut Vec<(Uuid, ratatui::layout::Rect)>,
    ) {
        match node {
            LayoutNode::Pane { id } => {
                result.push((*id, area));
            }
            LayoutNode::Split {
                direction,
                ratio,
                first,
                second,
            } => {
                let (first_area, second_area) = match direction {
                    SplitDirection::Horizontal => {
                        let split_row = (area.height as f32 * ratio) as u16;
                        let first = ratatui::layout::Rect::new(
                            area.x,
                            area.y,
                            area.width,
                            split_row.max(1),
                        );
                        let second = ratatui::layout::Rect::new(
                            area.x,
                            area.y + split_row,
                            area.width,
                            area.height.saturating_sub(split_row).max(1),
                        );
                        (first, second)
                    }
                    SplitDirection::Vertical => {
                        let split_col = (area.width as f32 * ratio) as u16;
                        let first = ratatui::layout::Rect::new(
                            area.x,
                            area.y,
                            split_col.max(1),
                            area.height,
                        );
                        let second = ratatui::layout::Rect::new(
                            area.x + split_col,
                            area.y,
                            area.width.saturating_sub(split_col).max(1),
                            area.height,
                        );
                        (first, second)
                    }
                };

                Self::calc_node_rects(first, first_area, result);
                Self::calc_node_rects(second, second_area, result);
            }
        }
    }

    /// Get tab count
    pub fn tab_count(&self) -> usize {
        self.tabs.len()
    }

    /// Get pane count in current tab
    pub fn pane_count(&self) -> usize {
        self.collect_pane_ids().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_layout() {
        let layout = LayoutEngine::new();
        assert_eq!(layout.tab_count(), 1);
        assert!(layout.active_pane_id().is_some());
    }

    #[test]
    fn test_split_horizontal() {
        let mut layout = LayoutEngine::new();
        layout.split_horizontal();
        assert_eq!(layout.pane_count(), 2);
    }

    #[test]
    fn test_split_vertical() {
        let mut layout = LayoutEngine::new();
        layout.split_vertical();
        assert_eq!(layout.pane_count(), 2);
    }

    #[test]
    fn test_new_tab() {
        let mut layout = LayoutEngine::new();
        layout.new_tab();
        assert_eq!(layout.tab_count(), 2);
        assert_eq!(layout.active_tab, 1);
    }

    #[test]
    fn test_tab_cycling() {
        let mut layout = LayoutEngine::new();
        layout.new_tab();
        layout.new_tab();
        assert_eq!(layout.active_tab, 2);
        layout.next_tab();
        assert_eq!(layout.active_tab, 0);
        layout.prev_tab();
        assert_eq!(layout.active_tab, 2);
    }

    #[test]
    fn test_focus_cycling() {
        let mut layout = LayoutEngine::new();
        let first_id = layout.active_pane_id().unwrap();
        layout.split_horizontal();
        let second_id = layout.active_pane_id().unwrap();
        assert_ne!(first_id, second_id);

        layout.focus_up();
        assert_eq!(layout.active_pane_id().unwrap(), first_id);
        layout.focus_down();
        assert_eq!(layout.active_pane_id().unwrap(), second_id);
    }
}
