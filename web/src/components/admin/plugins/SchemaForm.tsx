import { useEffect, useMemo, useRef, useState } from "react";

import { ArrowDown, ArrowUp, Loader2, Plus, Trash2 } from "lucide-react";

import type { PluginAdminForm, PluginAdminFormField, PluginAdminFormSection } from "@/api/types";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { useT } from "@/i18n";

import { OrderedMultiSelect } from "./OrderedMultiSelect";
import {
  addSlots,
  effectiveValue,
  evaluateShowWhen,
  removeSlotValues,
  swapSlotValues,
  validateSchemaValues,
  type SchemaOption,
} from "./schemaFormUtils";

type Props = {
  descriptor: PluginAdminForm;
  values: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  errors?: Record<string, string>;
  dynamicOptions?: Record<string, SchemaOption[]>;
  /**
   * True while the host is probing the connection for dynamic option lists
   * (root folders, quality profiles, tags). Drives per-field loading skeletons
   * on dynamic_options controls so the operator sees the form populate instead
   * of staring at empty selects.
   */
  optionsLoading?: boolean;
  idPrefix?: string;
  onValidityChange?: (valid: boolean) => void;
  /**
   * Fields the host owns for this form and does not show. Their values pass
   * through untouched, they are left out of validation (an admin could not fix
   * a field they cannot see), and a section left with no fields is dropped.
   */
  hiddenKeys?: readonly string[];
  /** Render every section open and without its Show/Hide toggle. */
  expandSections?: boolean;
  /**
   * Fields shown but not editable right now, each with the reason, which is
   * shown under the control (e.g. why a server's type cannot change).
   */
  lockedKeys?: Readonly<Record<string, string>>;
};

const NO_HIDDEN_KEYS: readonly string[] = [];
const NO_LOCKED_KEYS: Readonly<Record<string, string>> = {};

function optionsFor(
  field: PluginAdminFormField,
  dynamicOptions: Record<string, SchemaOption[]> | undefined,
): SchemaOption[] {
  if (field.dynamic_options) {
    return dynamicOptions?.[field.key] ?? field.options ?? [];
  }
  return field.options ?? [];
}

// A dynamic control is "pending" only when we're probing AND have nothing to
// show yet — so a refresh over already-loaded options never flashes a skeleton
// over the operator's current selection.
function isPending(
  field: PluginAdminFormField,
  options: SchemaOption[],
  optionsLoading: boolean | undefined,
): boolean {
  return Boolean(field.dynamic_options) && Boolean(optionsLoading) && options.length === 0;
}

// Stands in for a SELECT option whose value is the empty string.
const EMPTY_OPTION_VALUE = "\u0000empty";

// Loading placeholder for a single dynamic SELECT: a select-sized row with a
// spinner and a shimmer bar, so the field reads as "fetching from the service".
function SelectSkeleton() {
  return (
    <div
      aria-busy="true"
      className="border-input bg-muted/20 flex h-9 w-full items-center gap-2.5 rounded-md border px-3"
    >
      <Loader2 className="text-muted-foreground/70 h-3.5 w-3.5 shrink-0 animate-spin" />
      <Skeleton className="h-2.5 w-32 rounded-full" />
    </div>
  );
}

// FieldDescription is the muted helper text shown under a field or section
// label — shared so the markup can't drift between the field/switch/section
// renderers.
function FieldDescription({ text }: { text?: string }) {
  return text ? <p className="text-muted-foreground text-xs leading-relaxed">{text}</p> : null;
}

// Loading placeholder for a dynamic MULTI_SELECT (tags): a few shimmer chips.
function ChipsSkeleton() {
  return (
    <div aria-busy="true" className="flex flex-wrap gap-2">
      {["w-16", "w-12", "w-20", "w-14"].map((w) => (
        <Skeleton key={w} className={`h-7 rounded-md ${w}`} />
      ))}
    </div>
  );
}

function SchemaFormSection({
  section,
  values,
  fields,
  forceOpen,
  expanded,
  renderFields,
  addButton,
  onMoveUp,
  onMoveDown,
  onRemove,
}: {
  section: PluginAdminFormSection;
  values: Record<string, unknown>;
  fields: PluginAdminFormField[];
  forceOpen: boolean;
  expanded: boolean;
  renderFields: (keys: string[]) => React.ReactNode;
  /** The button that reveals the next slot, when this is a list's last shown one. */
  addButton?: React.ReactNode;
  /** Trade places with the slot before or after; set only for a list's slots that have one. */
  onMoveUp?: () => void;
  onMoveDown?: () => void;
  /** Remove this slot from its list; set only for a list's slots. */
  onRemove?: () => void;
}) {
  // null = operator hasn't toggled; fall back to collapsed_default. forceOpen
  // (the section has unresolved errors) always wins so setup can't be hidden.
  const t = useT();
  const [userOpen, setUserOpen] = useState<boolean | null>(null);

  if (!evaluateShowWhen(section.show_when, values, fields)) {
    return null;
  }

  // A list's slots stay collapsible in a form that opens its sections: a
  // long list is the reason to fold them.
  const isSlot = Boolean(section.add_group);
  const collapsible = section.collapsible && (!expanded || isSlot);
  // A slot whose first field is its name shows the name in its header, so a
  // folded slot can be told from the others.
  const first = isSlot ? fields.find((field) => field.key === section.field_keys[0]) : undefined;
  const firstValue = first?.control === "TEXT" ? values[first.key] : undefined;
  const slotName = typeof firstValue === "string" ? firstValue.trim() : "";
  const heading = slotName ? `${section.title}: ${slotName}` : section.title;
  const open = forceOpen || (userOpen ?? !section.collapsed_default);
  const showFields = collapsible ? open : true;

  const moveButtons = isSlot ? (
    <>
      <Button
        type="button"
        size="icon-xs"
        variant="ghost"
        disabled={!onMoveUp}
        aria-label={t("web.admin.settings.requests.list.moveUp")}
        title={t("web.admin.settings.requests.list.moveUp")}
        onClick={onMoveUp}
      >
        <ArrowUp aria-hidden="true" />
      </Button>
      <Button
        type="button"
        size="icon-xs"
        variant="ghost"
        disabled={!onMoveDown}
        aria-label={t("web.admin.settings.requests.list.moveDown")}
        title={t("web.admin.settings.requests.list.moveDown")}
        onClick={onMoveDown}
      >
        <ArrowDown aria-hidden="true" />
      </Button>
      <Button
        type="button"
        size="icon-xs"
        variant="ghost"
        disabled={!onRemove}
        aria-label={t("web.admin.settings.requests.shared.delete")}
        title={t("web.admin.settings.requests.shared.delete")}
        onClick={onRemove}
      >
        <Trash2 aria-hidden="true" />
      </Button>
    </>
  ) : null;

  // A list's slot folds as an accordion: the whole header is the trigger.
  // The move buttons sit beside the trigger, since a button cannot hold one.
  if (isSlot && collapsible) {
    return (
      <>
        <section className="border-border/70 bg-muted/10 rounded-lg border">
          <Accordion
            type="single"
            collapsible
            value={open ? section.key : ""}
            onValueChange={(value) => setUserOpen(value === section.key)}
          >
            <AccordionItem value={section.key} className="border-b-0">
              <div className="flex items-center gap-1 pe-3 [&>h3]:min-w-0 [&>h3]:flex-1">
                <AccordionTrigger className="items-center px-4 py-3 hover:no-underline">
                  <span className="grid gap-0.5">
                    <span className="text-foreground text-sm font-semibold">{heading}</span>
                    {section.description ? (
                      <span className="text-muted-foreground text-xs leading-relaxed font-normal">
                        {section.description}
                      </span>
                    ) : null}
                  </span>
                </AccordionTrigger>
                {moveButtons}
              </div>
              <AccordionContent className="px-4 pb-4">
                {renderFields(section.field_keys)}
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </section>
        {addButton}
      </>
    );
  }

  return (
    <>
      <section className="border-border/70 bg-muted/10 space-y-3 rounded-lg border p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="space-y-0.5">
            <Label className="text-foreground text-sm font-semibold">{heading}</Label>
            <FieldDescription text={section.description} />
          </div>
          <div className="flex shrink-0 items-center gap-1">
            {moveButtons}
            {collapsible ? (
              <Button type="button" size="xs" variant="ghost" onClick={() => setUserOpen(!open)}>
                {open
                  ? t("web.common.schemaForm.hideSection")
                  : t("web.common.schemaForm.showSection")}
              </Button>
            ) : null}
          </div>
        </div>
        {showFields ? renderFields(section.field_keys) : null}
      </section>
      {addButton}
    </>
  );
}

export function SchemaForm({
  descriptor,
  values,
  onChange,
  errors,
  dynamicOptions,
  optionsLoading,
  idPrefix = "schema",
  onValidityChange,
  hiddenKeys = NO_HIDDEN_KEYS,
  expandSections = false,
  lockedKeys = NO_LOCKED_KEYS,
}: Props) {
  const t = useT();
  const hidden = useMemo(() => new Set(hiddenKeys), [hiddenKeys]);
  // How many slots of each add group the admin has asked for with its button.
  const [revealedSlots, setRevealedSlots] = useState<Record<string, number>>({});
  const slots = useMemo(
    () => addSlots(descriptor, values, revealedSlots),
    [descriptor, values, revealedSlots],
  );
  const byKey = useMemo(() => {
    const map = new Map<string, PluginAdminFormField>();
    for (const field of descriptor.fields) {
      if (!hidden.has(field.key)) map.set(field.key, field);
    }
    return map;
  }, [descriptor.fields, hidden]);

  const clientErrors = useMemo(() => {
    const all = validateSchemaValues(descriptor, values, t);
    if (hidden.size === 0) return all;
    return Object.fromEntries(Object.entries(all).filter(([key]) => !hidden.has(key)));
  }, [descriptor, values, hidden, t]);

  const mergedErrors = useMemo(() => {
    return { ...clientErrors, ...(errors ?? {}) };
  }, [clientErrors, errors]);

  const valid = Object.keys(clientErrors).length === 0;

  // Report validity only when it actually changes, and key the effect on that
  // value alone. Callers routinely pass an inline arrow, which would otherwise
  // give the effect a new dependency every render; if that callback also sets
  // parent state, the pair loops until React throws "maximum update depth"
  // (error #185). Holding the callback in a ref keeps it current without making
  // its identity a trigger.
  const validityCallbackRef = useRef(onValidityChange);
  validityCallbackRef.current = onValidityChange;

  const lastReportedValidRef = useRef<boolean | null>(null);
  useEffect(() => {
    if (lastReportedValidRef.current === valid) return;
    lastReportedValidRef.current = valid;
    validityCallbackRef.current?.(valid);
  }, [valid]);

  function setField(key: string, value: unknown) {
    onChange({ ...values, [key]: value });
  }

  function lockNoteId(field: PluginAdminFormField): string {
    return `${idPrefix}-${field.key}-locked`;
  }

  // The reason a locked field cannot change, tied to its control.
  function renderLockNote(field: PluginAdminFormField): React.ReactNode {
    const reason = lockedKeys[field.key];
    return reason ? (
      <p id={lockNoteId(field)} className="text-muted-foreground text-xs">
        {reason}
      </p>
    ) : null;
  }

  function renderControl(field: PluginAdminFormField): React.ReactNode {
    const id = `${idPrefix}-${field.key}`;
    const locked = lockedKeys[field.key] !== undefined;
    const describedBy = locked ? lockNoteId(field) : undefined;

    if (field.control === "SELECT") {
      const options = optionsFor(field, dynamicOptions);
      if (isPending(field, options, optionsLoading)) {
        return <SelectSkeleton />;
      }
      // Radix reserves the empty string for "no selection", so an option
      // whose value is "" (a plugin's "Provider default") travels as a
      // stand-in and is written back as "".
      const current = String(effectiveValue(field, values) ?? "");
      const hasEmptyOption = options.some((option) => option.value === "");
      const toItem = (value: string) => (value === "" ? EMPTY_OPTION_VALUE : value);
      return (
        <Select
          value={hasEmptyOption ? toItem(current) : current}
          onValueChange={(nextValue) =>
            setField(field.key, nextValue === EMPTY_OPTION_VALUE ? "" : nextValue)
          }
          disabled={locked}
        >
          <SelectTrigger id={id} className="w-full" aria-describedby={describedBy}>
            <SelectValue
              placeholder={field.placeholder || t("web.common.schemaForm.selectPlaceholder")}
            />
          </SelectTrigger>
          <SelectContent>
            {options.map((option) => (
              <SelectItem key={option.value} value={toItem(option.value)}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      );
    }

    if (field.control === "MULTI_SELECT") {
      const options = optionsFor(field, dynamicOptions);
      if (isPending(field, options, optionsLoading)) {
        return <ChipsSkeleton />;
      }
      const current = effectiveValue(field, values);
      const selected = Array.isArray(current) ? current.map((v) => String(v)) : [];
      if (field.ordered && (options.length > 0 || selected.length > 0)) {
        return (
          <OrderedMultiSelect
            options={options}
            selected={selected}
            onChange={(next) => setField(field.key, next)}
            disabled={locked}
            describedBy={describedBy}
          />
        );
      }
      if (options.length === 0) {
        return (
          <p className="text-muted-foreground rounded-md border border-dashed px-3 py-2 text-xs">
            {t("web.common.schemaForm.noOptions")}
          </p>
        );
      }
      return (
        <div className="flex flex-wrap gap-2">
          {options.map((option) => {
            const isSelected = selected.includes(option.value);
            return (
              <Button
                key={option.value}
                type="button"
                size="xs"
                variant={isSelected ? "default" : "outline"}
                disabled={locked}
                aria-describedby={describedBy}
                onClick={() => {
                  const next = isSelected
                    ? selected.filter((value) => value !== option.value)
                    : [...selected, option.value];
                  setField(field.key, next);
                }}
              >
                {option.label}
              </Button>
            );
          })}
        </div>
      );
    }

    if (field.control === "TEXTAREA" || field.multiline) {
      return (
        <textarea
          id={id}
          className="border-border bg-background min-h-24 w-full rounded-md border px-3 py-2 text-sm"
          rows={field.rows && field.rows > 0 ? field.rows : 4}
          value={String(effectiveValue(field, values) ?? "")}
          placeholder={field.placeholder}
          onChange={(event) => setField(field.key, event.target.value)}
          disabled={locked}
          aria-describedby={describedBy}
        />
      );
    }

    return (
      <Input
        id={id}
        disabled={locked}
        aria-describedby={describedBy}
        type={
          field.control === "PASSWORD" || field.secret
            ? "password"
            : field.control === "NUMBER"
              ? "number"
              : "text"
        }
        value={String(effectiveValue(field, values) ?? "")}
        placeholder={field.placeholder}
        onChange={(event) => setField(field.key, event.target.value)}
      />
    );
  }

  // A non-switch field: label + optional description stacked above the control.
  function renderField(field: PluginAdminFormField): React.ReactNode {
    const err = mergedErrors[field.key];
    // A field that only appears because its show_when passed reads as nested
    // under whatever toggle gates it (e.g. the anime overrides under anime_enabled).
    const nested = Boolean(field.show_when);
    return (
      <div
        key={field.key}
        data-nested={nested ? "true" : undefined}
        className={cn("space-y-2", nested && "border-border/60 ms-0.5 border-s ps-3")}
      >
        <div className="space-y-1">
          <Label htmlFor={`${idPrefix}-${field.key}`}>{field.label || field.key}</Label>
          <FieldDescription text={field.description} />
        </div>
        {renderControl(field)}
        {renderLockNote(field)}
        {err ? <p className="text-destructive text-xs">{err}</p> : null}
      </div>
    );
  }

  // A switch field as a single settings row: label + description at the start,
  // the toggle at the end. No outer border — the group container owns it.
  function renderSwitchRow(field: PluginAdminFormField): React.ReactNode {
    const id = `${idPrefix}-${field.key}`;
    const err = mergedErrors[field.key];
    return (
      <div key={field.key} className="px-3.5 py-3 transition-colors">
        <div className="flex items-start gap-3">
          <Switch
            id={id}
            className="mt-0.5 shrink-0"
            checked={Boolean(effectiveValue(field, values))}
            onCheckedChange={(checked) => setField(field.key, checked)}
            disabled={lockedKeys[field.key] !== undefined}
            aria-describedby={lockedKeys[field.key] !== undefined ? lockNoteId(field) : undefined}
          />
          <div className="min-w-0 space-y-0.5">
            <Label htmlFor={id} className="cursor-pointer font-medium">
              {field.label || field.key}
            </Label>
            <FieldDescription text={field.description} />
            {renderLockNote(field)}
          </div>
        </div>
        {err ? <p className="text-destructive ms-11 mt-1.5 text-xs">{err}</p> : null}
      </div>
    );
  }

  // Render an ordered field list, collapsing consecutive switches into one
  // bordered, divided container so toggles read as a cohesive group instead of
  // a column of separate boxes. Honors show_when on each field.
  function renderFieldList(fields: PluginAdminFormField[]): React.ReactNode {
    const visible = fields.filter((field) =>
      evaluateShowWhen(field.show_when, values, descriptor.fields),
    );
    const nodes: React.ReactNode[] = [];
    let run: PluginAdminFormField[] = [];
    // Key switch groups by their position in the list, not by their first
    // field's key — so revealing/hiding a show_when switch within a run keeps the
    // container's identity stable (no remount, no focus loss on the toggle).
    let groupIndex = 0;

    const flushSwitches = () => {
      if (run.length === 0) return;
      const group = run;
      run = [];
      nodes.push(
        <div
          key={`switch-group-${groupIndex++}`}
          className="divide-border/70 bg-card divide-y overflow-hidden rounded-lg border"
        >
          {group.map((field) => renderSwitchRow(field))}
        </div>,
      );
    };

    for (const field of visible) {
      if (field.control === "SWITCH") {
        run.push(field);
      } else {
        flushSwitches();
        nodes.push(renderField(field));
      }
    }
    flushSwitches();

    if (nodes.length === 0) return null;
    return <div className="grid gap-4">{nodes}</div>;
  }

  // The button after a list's last shown slot. It reveals the next one.
  function renderAddButton(section: PluginAdminFormSection): React.ReactNode {
    const add = slots.addAfter.get(section.key);
    if (!add) return null;
    const shown = (descriptor.sections ?? []).filter(
      (candidate) => candidate.add_group === add.group && !slots.hidden.has(candidate.key),
    ).length;
    return (
      <div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          onClick={() => setRevealedSlots((current) => ({ ...current, [add.group]: shown + 1 }))}
        >
          <Plus aria-hidden="true" />
          {add.label}
        </Button>
      </div>
    );
  }

  // Trades a slot's values with the shown slot before (-1) or after (+1) it
  // in its list. Undefined when there is none.
  function slotMover(section: PluginAdminFormSection, step: -1 | 1): (() => void) | undefined {
    if (!section.add_group) return undefined;
    const shown = (descriptor.sections ?? []).filter(
      (candidate) => candidate.add_group === section.add_group && !slots.hidden.has(candidate.key),
    );
    const other = shown[shown.indexOf(section) + step];
    if (!other) return undefined;
    return () => onChange(swapSlotValues(section, other, values));
  }

  // Removes a slot from its list: the shown slots after it move up, and the
  // list shows one slot fewer unless this was its only one.
  function slotRemover(section: PluginAdminFormSection): (() => void) | undefined {
    const group = section.add_group;
    if (!group) return undefined;
    const shown = (descriptor.sections ?? []).filter(
      (candidate) => candidate.add_group === group && !slots.hidden.has(candidate.key),
    );
    return () => {
      setRevealedSlots((current) => ({ ...current, [group]: Math.max(1, shown.length - 1) }));
      onChange(removeSlotValues(shown, shown.indexOf(section), values));
    };
  }

  const sections = descriptor.sections ?? [];
  const groupedKeys = new Set<string>();
  for (const section of sections) {
    for (const key of section.field_keys) {
      groupedKeys.add(key);
    }
  }
  const ungroupedFields = descriptor.fields.filter(
    (field) => !groupedKeys.has(field.key) && !hidden.has(field.key),
  );

  const resolveKeys = (keys: string[]): PluginAdminFormField[] =>
    keys
      .map((key) => byKey.get(key))
      .filter((field): field is PluginAdminFormField => Boolean(field));

  return (
    <div className="grid gap-5">
      {ungroupedFields.length > 0 ? renderFieldList(ungroupedFields) : null}
      {sections
        .filter(
          (section) => resolveKeys(section.field_keys).length > 0 && !slots.hidden.has(section.key),
        )
        .map((section) => (
          <SchemaFormSection
            key={section.key}
            section={section}
            values={values}
            fields={descriptor.fields}
            forceOpen={section.field_keys.some((key) => mergedErrors[key] != null)}
            expanded={expandSections}
            renderFields={(keys) => renderFieldList(resolveKeys(keys))}
            addButton={renderAddButton(section)}
            onMoveUp={slotMover(section, -1)}
            onMoveDown={slotMover(section, 1)}
            onRemove={slotRemover(section)}
          />
        ))}
    </div>
  );
}
