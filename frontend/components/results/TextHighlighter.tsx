import React from 'react';

interface TextHighlighterProps {
    text: string;
    riskyPhrases: string[];
}

export const TextHighlighter: React.FC<TextHighlighterProps> = ({ text, riskyPhrases }) => {
    if (!riskyPhrases || riskyPhrases.length === 0) {
        return <p className="font-mono text-sm opacity-90 whitespace-pre-wrap leading-relaxed">{text}</p>;
    }

    // Create a regex from phrases (case insensitive)
    // Escape special chars in phrases
    const escapeRegExp = (string: string) => string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`(${riskyPhrases.map(escapeRegExp).join('|')})`, 'gi');

    const parts = text.split(pattern);

    return (
        <p className="font-mono text-sm opacity-90 whitespace-pre-wrap leading-relaxed">
            {parts.map((part, index) => {
                const isRisky = riskyPhrases.some(phrase => phrase.toLowerCase() === part.toLowerCase());
                return isRisky ? (
                    <span key={index} className="bg-red-500/20 text-red-700 dark:text-red-300 px-1 rounded font-bold border-b-2 border-red-500">
                        {part}
                    </span>
                ) : (
                    <span key={index}>{part}</span>
                );
            })}
        </p>
    );
};
