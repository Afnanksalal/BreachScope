"use client";

import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Check, ChevronDown } from "lucide-react";
import { clsx } from "clsx";

export interface CustomSelectOption {
  value: string;
  label: string;
  description?: string;
  disabled?: boolean;
}

interface CustomSelectProps {
  value: string;
  options: CustomSelectOption[];
  onChange: (value: string) => void;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  buttonClassName?: string;
  menuClassName?: string;
  ariaLabel?: string;
}

export function CustomSelect({
  value,
  options,
  onChange,
  placeholder = "Select",
  disabled = false,
  className,
  buttonClassName,
  menuClassName,
  ariaLabel,
}: CustomSelectProps) {
  const id = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const selected = useMemo(() => options.find((option) => option.value === value), [options, value]);
  const enabledOptions = useMemo(() => options.filter((option) => !option.disabled), [options]);
  const selectedEnabledIndex = Math.max(0, enabledOptions.findIndex((option) => option.value === value));
  const [activeIndex, setActiveIndex] = useState(selectedEnabledIndex);

  useEffect(() => {
    if (!open) return;

    function onPointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") setOpen(false);
    }

    document.addEventListener("pointerdown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("pointerdown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  function choose(nextValue: string) {
    onChange(nextValue);
    setOpen(false);
  }

  function toggleOpen() {
    if (open) {
      setOpen(false);
    } else {
      setActiveIndex(selectedEnabledIndex);
      setOpen(true);
    }
  }

  function move(delta: number) {
    if (enabledOptions.length === 0) return;
    setActiveIndex((current) => (current + delta + enabledOptions.length) % enabledOptions.length);
    setOpen(true);
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLButtonElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
    } else if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (open) {
        const active = enabledOptions[activeIndex];
        if (active) choose(active.value);
      } else {
        setActiveIndex(selectedEnabledIndex);
        setOpen(true);
      }
    }
  }

  return (
    <div ref={rootRef} className={clsx("relative min-w-0", className)}>
      <button
        type="button"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={`${id}-listbox`}
        disabled={disabled || enabledOptions.length === 0}
        onClick={toggleOpen}
        onKeyDown={handleKeyDown}
        className={clsx(
          "flex w-full items-center justify-between gap-3 rounded-lg border border-white/[0.08] bg-black/40 px-3 py-2 text-left text-sm text-white outline-none transition-colors",
          "hover:border-white/[0.14] hover:bg-white/[0.045] focus:border-white/20 focus:bg-white/[0.055]",
          "disabled:cursor-not-allowed disabled:opacity-40",
          buttonClassName,
        )}
      >
        <span className="min-w-0">
          <span className={clsx("block truncate", selected ? "text-white/85" : "text-white/28")}>
            {selected?.label ?? placeholder}
          </span>
          {selected?.description && (
            <span className="mt-0.5 block truncate text-xs text-white/32">{selected.description}</span>
          )}
        </span>
        <ChevronDown className={clsx("h-4 w-4 shrink-0 text-white/35 transition-transform", open && "rotate-180 text-white/65")} />
      </button>

      {open && (
        <div
          id={`${id}-listbox`}
          role="listbox"
          aria-label={ariaLabel ?? placeholder}
          className={clsx(
            "absolute left-0 right-0 z-50 mt-2 max-h-72 overflow-y-auto rounded-lg border border-white/[0.10] bg-[#050707]/95 p-1.5 shadow-2xl shadow-black/50 backdrop-blur-xl",
            menuClassName,
          )}
        >
          {options.length === 0 ? (
            <div className="px-3 py-2 text-sm text-white/30">No options</div>
          ) : (
            options.map((option) => {
              const selectedOption = option.value === value;
              const activeOption = enabledOptions[activeIndex]?.value === option.value;
              return (
                <button
                  key={option.value}
                  type="button"
                  role="option"
                  aria-selected={selectedOption}
                  disabled={option.disabled}
                  onMouseEnter={() => {
                    const nextIndex = enabledOptions.findIndex((enabled) => enabled.value === option.value);
                    if (nextIndex >= 0) setActiveIndex(nextIndex);
                  }}
                  onClick={() => choose(option.value)}
                  className={clsx(
                    "flex w-full items-start gap-3 rounded-md px-3 py-2.5 text-left transition-colors",
                    selectedOption ? "bg-white/[0.09] text-white" : activeOption ? "bg-white/[0.055] text-white/82" : "text-white/55 hover:bg-white/[0.05] hover:text-white/80",
                    option.disabled && "cursor-not-allowed opacity-35",
                  )}
                >
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{option.label}</span>
                    {option.description && (
                      <span className="mt-0.5 block line-clamp-2 text-xs leading-4 text-white/32">{option.description}</span>
                    )}
                  </span>
                  <Check className={clsx("mt-0.5 h-4 w-4 shrink-0", selectedOption ? "text-white" : "text-transparent")} />
                </button>
              );
            })
          )}
        </div>
      )}
    </div>
  );
}
