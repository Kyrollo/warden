import React, { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Copy, Check, Maximize2, Minimize2 } from 'lucide-react';

interface MarkdownRendererProps {
  content: string;
  className?: string;
  expandable?: boolean;
  defaultMaxHeight?: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({
  content,
  className = '',
  expandable = true,
  defaultMaxHeight = 'max-h-[500px]',
}) => {
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback
    }
  };

  return (
    <div className={`relative group ${className}`}>
      <div className="flex items-center justify-end gap-1.5 mb-1.5 opacity-90">
        {expandable && (
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors border border-slate-800"
            title={isExpanded ? 'Collapse' : 'Expand full output'}
          >
            {isExpanded ? (
              <>
                <Minimize2 className="w-3 h-3" />
                <span>Collapse</span>
              </>
            ) : (
              <>
                <Maximize2 className="w-3 h-3" />
                <span>Show Full</span>
              </>
            )}
          </button>
        )}
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors border border-slate-800"
          title="Copy text"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-emerald-400" />
              <span className="text-emerald-400 font-medium">Copied!</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>

      <div
        className={`overflow-y-auto pr-1 transition-all ${
          isExpanded ? 'max-h-none' : defaultMaxHeight
        } prose prose-invert prose-sm max-w-none text-slate-200 leading-relaxed font-sans`}
      >
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            h1: ({ ...props }) => (
              <h1 className="text-base font-bold mt-2 mb-1 text-slate-100 border-b border-slate-800 pb-1" {...props} />
            ),
            h2: ({ ...props }) => (
              <h2 className="text-sm font-semibold mt-2 mb-1 text-slate-100" {...props} />
            ),
            h3: ({ ...props }) => (
              <h3 className="text-xs font-semibold mt-1.5 mb-0.5 text-slate-200" {...props} />
            ),
            p: ({ ...props }) => (
              <p className="my-1 text-xs text-slate-300 leading-relaxed font-sans" {...props} />
            ),
            ul: ({ ...props }) => (
              <ul className="list-disc list-inside my-1 space-y-0.5 text-xs text-slate-300 pl-1" {...props} />
            ),
            ol: ({ ...props }) => (
              <ol className="list-decimal list-inside my-1 space-y-0.5 text-xs text-slate-300 pl-1" {...props} />
            ),
            li: ({ ...props }) => <li className="my-0.5 text-xs" {...props} />,
            blockquote: ({ ...props }) => (
              <blockquote className="border-l-2 border-rose-500 pl-3 my-2 italic text-slate-400 text-xs bg-slate-900/60 py-1 rounded-r" {...props} />
            ),
            code: ({ inline, ...props }: any) => {
              if (inline) {
                return (
                  <code className="bg-slate-900 text-rose-400 px-1 py-0.5 rounded font-mono text-[11px] border border-slate-800" {...props} />
                );
              }
              return (
                <div className="relative my-2 rounded-lg bg-slate-950 border border-slate-800 p-3 overflow-x-auto">
                  <pre className="font-mono text-xs text-slate-100 m-0">
                    <code {...props} />
                  </pre>
                </div>
              );
            },
            table: ({ ...props }) => (
              <div className="overflow-x-auto my-2 rounded border border-slate-800">
                <table className="w-full text-xs text-left divide-y divide-slate-800" {...props} />
              </div>
            ),
            th: ({ ...props }) => (
              <th className="px-2 py-1 bg-slate-900 font-semibold text-slate-200 text-[11px]" {...props} />
            ),
            td: ({ ...props }) => (
              <td className="px-2 py-1 border-t border-slate-800/60 text-slate-300 text-xs" {...props} />
            ),
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </div>
  );
};
