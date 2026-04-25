import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { StatsCard } from "@/components/dashboard/StatsCard";

vi.mock("framer-motion", () => ({
  motion: {
    div: ({ children, className }: { children: React.ReactNode; className?: string }) => (
      <div className={className}>{children}</div>
    ),
  },
}));

describe("StatsCard", () => {
  it("renders title and value", () => {
    render(<StatsCard title="Total Scans" value={42} />);
    expect(screen.getByText("Total Scans")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });

  it("renders sub text when provided", () => {
    render(<StatsCard title="Issues" value={7} sub="last 30 days" />);
    expect(screen.getByText("last 30 days")).toBeInTheDocument();
  });

  it("does not render sub text when omitted", () => {
    render(<StatsCard title="Issues" value={7} />);
    expect(screen.queryByText("last 30 days")).not.toBeInTheDocument();
  });

  it("renders trend label and applies red class for positive trend", () => {
    const { container } = render(
      <StatsCard title="Bugs" value={5} trend={{ value: 3, label: "new this week" }} />
    );
    // use regex because the label is adjacent to count text nodes
    expect(screen.getByText(/new this week/)).toBeInTheDocument();
    // positive trend → red
    expect(container.querySelector(".text-red-400")).not.toBeNull();
  });

  it("renders green class for negative trend", () => {
    const { container } = render(
      <StatsCard title="Bugs" value={0} trend={{ value: -2, label: "fewer" }} />
    );
    expect(container.querySelector(".text-green-400")).not.toBeNull();
    expect(screen.getByText(/fewer/)).toBeInTheDocument();
  });

  it("does not render trend section when trend is omitted", () => {
    render(<StatsCard title="Score" value="A+" />);
    expect(screen.queryByText(/new this week/)).not.toBeInTheDocument();
  });

  it("accepts string value", () => {
    render(<StatsCard title="Grade" value="A+" />);
    expect(screen.getByText("A+")).toBeInTheDocument();
  });

  it("applies red accent border class", () => {
    const { container } = render(<StatsCard title="Critical" value={1} accent="red" />);
    const card = container.firstChild as HTMLElement;
    expect(card.className).toContain("border-red-500");
  });

  it("applies blue accent border class", () => {
    const { container } = render(<StatsCard title="Info" value={0} accent="blue" />);
    const card = container.firstChild as HTMLElement;
    expect(card.className).toContain("border-breach-500");
  });

  it("shows absolute value for negative trend (no minus sign visible)", () => {
    render(<StatsCard title="T" value={0} trend={{ value: -5, label: "fixed" }} />);
    expect(screen.getByText(/fixed/)).toBeInTheDocument();
    // Should not show "-5"
    expect(screen.queryByText(/-5/)).not.toBeInTheDocument();
  });
});
