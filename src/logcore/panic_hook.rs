use crate::logcore::entry::{ErrorInfo, LogEntry, StackFrame};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

static HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the global panic hook to capture uncaught crashes as logcore ERROR events.
pub fn install() {
    if HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let prev_hook = panic::take_hook();

    panic::set_hook(Box::new(move |panic_info| {
        let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "Unhandled panic in application thread".to_string()
        };

        let location_frame = panic_info.location().map(|loc| StackFrame {
            function: "<panic>".to_string(),
            file: loc.file().to_string(),
            line: loc.line(),
            column: loc.column(),
            in_app: true,
        });

        let stack = match location_frame {
            Some(f) => vec![f],
            None => vec![],
        };

        let error = ErrorInfo {
            error_type: "Panic".to_string(),
            message: message.clone(),
            stack,
        };

        let entry = LogEntry::new(
            "ERROR",
            format!("Panic: {}", message),
            None,
            Some(error),
            None,
            None,
        );

        crate::logcore::log_entry(entry);
        crate::logcore::flush();

        // Forward to the previous panic hook to preserve default crash output
        prev_hook(panic_info);
    }));
}
