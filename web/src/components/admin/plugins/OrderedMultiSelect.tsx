import { DndContext } from "@dnd-kit/core";
import { SortableContext, useSortable, verticalListSortingStrategy } from "@dnd-kit/sortable";
import { CSS } from "@dnd-kit/utilities";
import { GripVertical, Plus, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useSortableList } from "@/hooks/useSortableList";
import { useT } from "@/i18n";

import type { SchemaOption } from "./schemaFormUtils";

function identity(value: string): string {
  return value;
}

function SortableValue({
  value,
  label,
  position,
  disabled,
  onRemove,
}: {
  value: string;
  label: string;
  position: number;
  disabled: boolean;
  onRemove: () => void;
}) {
  const t = useT();
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({
    id: value,
    disabled,
  });
  const style: React.CSSProperties = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.4 : 1,
  };
  return (
    <li
      ref={setNodeRef}
      style={style}
      className="bg-card flex items-center gap-2 rounded-md border px-2 py-1.5 text-sm"
    >
      <button
        type="button"
        aria-label={t("web.admin.libraries.list.dragToReorder")}
        title={t("web.admin.libraries.list.dragToReorder")}
        disabled={disabled}
        className="hover:bg-surface-hover cursor-grab touch-none rounded-md p-0.5 transition-colors disabled:cursor-default"
        {...attributes}
        {...listeners}
      >
        <GripVertical aria-hidden="true" className="text-muted-foreground size-4" />
      </button>
      <span className="text-muted-foreground w-4 text-end text-xs tabular-nums">{position}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      <Button
        type="button"
        size="icon-xs"
        variant="ghost"
        disabled={disabled}
        aria-label={t("web.admin.settings.requests.shared.delete")}
        title={t("web.admin.settings.requests.shared.delete")}
        onClick={onRemove}
      >
        <X aria-hidden="true" />
      </Button>
    </li>
  );
}

/**
 * A multi-select whose order matters. The chosen values are a list that can
 * be put in order by dragging, or with the keyboard on a row's handle; the
 * options not chosen yet are buttons that add to the end of it.
 */
export function OrderedMultiSelect({
  options,
  selected,
  onChange,
  disabled = false,
  describedBy,
}: {
  options: SchemaOption[];
  selected: string[];
  onChange: (next: string[]) => void;
  disabled?: boolean;
  describedBy?: string;
}) {
  const { sensors, collisionDetection, handleDragEnd } = useSortableList(
    selected,
    identity,
    onChange,
  );
  // A chosen value the options no longer list keeps its place, shown as it is stored.
  const labels = new Map(options.map((option) => [option.value, option.label]));
  const unchosen = options.filter((option) => !selected.includes(option.value));

  return (
    <div className="grid gap-2" aria-describedby={describedBy}>
      {selected.length > 0 ? (
        <DndContext
          sensors={sensors}
          collisionDetection={collisionDetection}
          onDragEnd={handleDragEnd}
        >
          <SortableContext items={selected} strategy={verticalListSortingStrategy}>
            <ol className="grid gap-1.5">
              {selected.map((value, index) => (
                <SortableValue
                  key={value}
                  value={value}
                  label={labels.get(value) ?? value}
                  position={index + 1}
                  disabled={disabled}
                  onRemove={() => onChange(selected.filter((other) => other !== value))}
                />
              ))}
            </ol>
          </SortableContext>
        </DndContext>
      ) : null}
      {unchosen.length > 0 ? (
        <div className="flex flex-wrap gap-2">
          {unchosen.map((option) => (
            <Button
              key={option.value}
              type="button"
              size="xs"
              variant="outline"
              disabled={disabled}
              onClick={() => onChange([...selected, option.value])}
            >
              <Plus aria-hidden="true" />
              {option.label}
            </Button>
          ))}
        </div>
      ) : null}
    </div>
  );
}
