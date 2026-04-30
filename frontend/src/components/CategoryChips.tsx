interface CategoryChipsProps {
  categories: string[];
}

export function CategoryChips({ categories }: CategoryChipsProps) {
  if (categories.length === 0) {
    return null;
  }

  return (
    <div className="category-chips" aria-label="Behavior categories">
      {categories.slice(0, 8).map((category) => (
        <span key={category}>{category}</span>
      ))}
    </div>
  );
}

