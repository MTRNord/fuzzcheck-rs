mod framework;
mod hlist;
mod horizontal_list_view;
mod text_field_view;

mod error_view;
mod fuzzing;
mod initialized;
mod preinit;
mod run_fuzz;

mod app;
mod events;
mod fuzz_target_comm;

use std::{io::{self, Stdout}, process::Stdio, time::Duration};
use std::{error::Error, path::PathBuf};

use events::EXIT_KEY;
use fuzzcheck_common::ipc::TuiMessage;
use fuzzing::FuzzingView;

use crate::{strings_from_config, ui::framework::ViewState};

// use comm::FuzzingEvent;
use termion::{input::MouseTerminal, raw::RawTerminal};
use termion::raw::IntoRawMode;
use termion::screen::AlternateScreen;

use tui::{Terminal, backend::{Backend, TermionBackend}, layout::Rect};

use self::{framework::Theme};


type TerminalAlias = Terminal<TermionBackend<AlternateScreen<MouseTerminal<RawTerminal<Stdout>>>>>;

fn set_ui_terminal(raw: bool) -> Result<TerminalAlias, Box<dyn Error>> {
    let stdout = io::stdout().into_raw_mode()?;
    if raw { stdout.activate_raw_mode()? } else { stdout.suspend_raw_mode()? };
    let stdout = MouseTerminal::from(stdout);
    let stdout = AlternateScreen::from(stdout);
    let backend = TermionBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

pub fn launch_app(root_path: PathBuf) -> Result<(), Box<dyn Error>> {
    // Terminal initialization
    let mut terminal = set_ui_terminal(true)?;

    let mut events = events::Events::<TuiMessage>::new();

    let mut state = app::State::new(root_path, events.tx.clone());

    let mut child_process = None;

    'main_loop: loop {
        terminal.draw(|f| {
            state.draw(f, &Theme::primary(), f.size());
        })?;

        // blocking
        let event = events.next()?;

        // first check if the event needs to be intercepted,
        // for example if it's the exit key
        match &event {
            events::Event::UserInput(key) => {
                if key == &EXIT_KEY {
                    break 'main_loop;
                }
            }
            _ => {}
        }

        if let Some(update) = state.convert_in_message(event) {
            if let Some(out_message) = state.update(update) {
                match out_message {
                    app::OutMessage::Quit => {
                        break 'main_loop;
                    }
                    app::OutMessage::StartFuzzing { root, target_name, config } => {
                        if child_process.is_none() { 
                            // Terminal initialization
                            terminal.clear()?;
                            std::mem::drop(terminal); 

                            root.build_command(target_name.as_ref(), &config, &Stdio::inherit).unwrap();

                            let (listener, socket_address) = fuzz_target_comm::create_listener();

                            events.add_stream(move |tx| {
                                fuzz_target_comm::receive_fuzz_target_messages(listener, tx)
                            });

                            let out = state.update(app::Update::ChangePhase(app::Phase::Fuzzing(FuzzingView::new())));
                            assert!(out.is_none());

                            let mut config = config;
                            config.socket_address = Some(socket_address);

                            let child = root.launch_executable(target_name.as_ref(), &config, &Stdio::null).unwrap();
                            child_process = Some(child);

                            terminal = set_ui_terminal(true)?;
                        } else {
                            panic!()
                        }
                    }
                }
            }
        } else {
        }
    }

    Ok(())
}
