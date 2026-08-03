//! Ghidrust plugin‑event bus.
//!
//! Providers announce cursor / selection / program‑mutation events by pushing a
//! `GhidrustEvent` onto the app's `event_bus`. Each frame the app drains the bus and
//! fans events out to every subscribed pane (Symbol Tree, Bookmarks, Decompiler, etc.)
//! so cross‑window sync is centralised.
//!
//! The bus is a plain `Vec<GhidrustEvent>`; each frame `GhidrustApp::drain_events`
//! fans events out (listing focus status, decompiler cache invalidation, etc.).

use crate::nav::NavLocation;

/// One published event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GhidrustEvent {
    /// Cursor / focused location changed.
    ///
    /// `source` identifies the pane that emitted the event so subscribers can avoid
    /// echo loops.
    CursorMoved {
        source: EventSource,
        location: NavLocation,
    },
    /// Program was mutated — every downstream pane invalidates its cache.
    ProgramMutated { kind: MutationKind },
    /// A new program was activated / opened.
    ProgramActivated { name: String },
}

/// Pane / plugin that emitted an event.
///
/// Only sources that currently publish are listed — add a variant when a producer lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventSource {
    Listing,
    Navigation,
}

/// Kinds of program mutation subscribers care about (drives cache invalidation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationKind {
    Rename { va: u64, new_name: String },
    Retype { va: u64, type_desc: String },
    CommentChanged { va: u64 },
    BookmarkAdded { va: u64 },
    BookmarkRemoved { va: u64 },
}

/// Simple in-memory bus. Producers push; consumers drain each frame.
#[derive(Debug, Default, Clone)]
pub struct EventBus {
    events: Vec<GhidrustEvent>,
}

impl EventBus {
    pub const fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn publish(&mut self, event: GhidrustEvent) {
        self.events.push(event);
        // Cap bus growth in case a consumer forgets to drain.
        if self.events.len() > 4096 {
            let excess = self.events.len() - 4096;
            self.events.drain(0..excess);
        }
    }

    /// Take everything currently queued.
    pub fn drain(&mut self) -> Vec<GhidrustEvent> {
        std::mem::take(&mut self.events)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(va: u64) -> NavLocation {
        NavLocation::new(va)
    }

    #[test]
    fn bus_publishes_and_drains() {
        let mut bus = EventBus::new();
        assert!(bus.is_empty());
        bus.publish(GhidrustEvent::CursorMoved {
            source: EventSource::Listing,
            location: loc(0x1000),
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::CommentChanged { va: 0x1000 },
        });
        assert_eq!(bus.len(), 2);
        let drained = bus.drain();
        assert_eq!(drained.len(), 2);
        assert!(bus.is_empty(), "drain empties the queue");
    }

    #[test]
    fn bus_caps_growth() {
        let mut bus = EventBus::new();
        for i in 0..5000u64 {
            bus.publish(GhidrustEvent::CursorMoved {
                source: EventSource::Listing,
                location: loc(i),
            });
        }
        assert!(bus.len() <= 4096, "bus must self-limit to prevent leaks");
    }

    #[test]
    fn every_event_variant_constructible() {
        let mut bus = EventBus::new();
        bus.publish(GhidrustEvent::CursorMoved {
            source: EventSource::Listing,
            location: loc(0x1000),
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Rename {
                va: 0x1000,
                new_name: "foo".into(),
            },
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::Retype {
                va: 0x1000,
                type_desc: "int*".into(),
            },
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::CommentChanged { va: 0x1000 },
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::BookmarkAdded { va: 0x1000 },
        });
        bus.publish(GhidrustEvent::ProgramMutated {
            kind: MutationKind::BookmarkRemoved { va: 0x1000 },
        });
        bus.publish(GhidrustEvent::ProgramActivated {
            name: "hello.exe".into(),
        });
        bus.publish(GhidrustEvent::CursorMoved {
            source: EventSource::Navigation,
            location: loc(0x2000),
        });
        assert_eq!(bus.len(), 8);
    }
}
