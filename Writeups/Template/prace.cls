%%% Partnership for Advanced Computing in Europe 
%%%   www.prace-ri.eu
%%%
%%% LaTeX document class for a PRACE white paper.
%%%
%%% (c) CSC - IT Center for Science Ltd.
%%%     author: Martti Louhivuori (martti.louhivuori@csc.fi)
%%% (c) JSC/PRACE
%%%     author: Dirk Broemmel (prace-pmo@fz-juelich.de)
%%%
%%% Requires: LaTeX2e
%%%           geometry, graphicx, ifthen, booktabs
%%%
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{prace}[2022/05/18 PRACE Whitepaper class]

\DeclareOption{onecolumn}{\OptionNotUsed}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\ProcessOptions\relax

% default font-size for main body text of the current template is 10pt
\LoadClass[a4paper,10pt]{article}

% A4: 210x297mm - 25mm margins top, left, right, 20mm on bottom
\RequirePackage{geometry}
\geometry{a4paper, total={165mm,247mm},
   left=25mm, top=25mm, right=25mm, bottom=20mm,
   footskip=8mm
}

\RequirePackage{siunitx}
\RequirePackage{graphicx}
\RequirePackage{ifthen}
\RequirePackage{booktabs}
\RequirePackage{iftex}

% select a font close to Times New Roman (this will depend on the TeX interpreter, more to come)
\ifpdftex
   \RequirePackage{mathptmx}
\fi
\ifxetex
   \RequirePackage{fontspec}
   \setmainfont{FreeSerif} % this looks a lot like mathptmx, though metric not fully compatible
   %\setmainfont{Liberation Serif} % this looks less like mathptmx, but has metric compatibility
\fi
\ifluatex
   \RequirePackage{fontspec}
   \setmainfont{FreeSerif}
\fi

% try and make sure \maketitle works when using UTF-8 characters and pdflatex/lualatex
\ifpdftex
   \RequirePackage[T1]{fontenc}
\fi
\ifluatex
   \RequirePackage[utf8]{luainputenc}
\fi

% spacing between paragraphs and indents
\RequirePackage{parskip}

% page numbering
\pagenumbering{arabic}

% default values
\def\authoremail{author@example.com}
\def\refdoi{}

% date on bottom right, page number in the middle, DOI on the left
\RequirePackage{fancyhdr}
\pagestyle{fancy}
\fancyhead[L,C,R]{}
\renewcommand{\headrulewidth}{0pt}
\fancyfoot[C]{\thepage}
\fancyfoot[R]{\@date}
\fancyfoot[L]{\refdoi{}}

% DOI as obtained from Zenodo or alike (PMO will reserve one first, then add here)
\newcommand{\doi}[1]{\renewcommand\refdoi{#1}}

% internal counters
\newcounter{praceauth}
\setcounter{praceauth}{0}
\renewcommand\thepraceauth{\alph{praceauth}}
\newcounter{praceaffi}
\setcounter{praceaffi}{0}
\renewcommand\thepraceaffi{\alph{praceaffi}}
\newcounter{pracetmp}
\setcounter{pracetmp}{0}
\renewcommand\thepracetmp{\alph{pracetmp}}

% author contact details
\newcommand{\email}[1]{\renewcommand\authoremail{#1}}

% tag corresponding author
\newif\if@iscorresponding
\@iscorrespondingfalse
\newif\if@hascorresponding
\@hascorrespondingfalse
\newcommand\corresponding[0]{\@iscorrespondingtrue\@hascorrespondingtrue}
% corresponding author footnote
\long\def\authorfootnote{%
	\def\thefootnote{\fnsymbol{footnote}}%
	\csname c@\@mpfn\endcsname 1\relax%
	\protected@xdef\@thefnmark{\thempfn}%
	\@footnotetext}
% corresponding author contact detail footnote
\def\authorcontact{%
	\authorfootnote{Corresponding author, %
	e-mail: \authoremail{}}
	}

% tmp flag
\newif\if@praceflag
\@praceflagfalse

% convert integers to letters
\def\csvitoalist{}
\newcommand\csvitoa[1]{
	\def\csvitoalist{}
	\@for\name:=#1\do{
		\setcounter{pracetmp}{\name}
		\if@praceflag
			\edef\csvitoalist{\csvitoalist,\thepracetmp}
		\else
			\edef\csvitoalist{\thepracetmp}
			\@praceflagtrue
		\fi}
	\@praceflagfalse
	\csvitoalist
	}

% store author definitions for later use
\def\authorlist{}
\def\tmpname{}
\renewcommand\author[2][a]{%
	%
	\def\alfalist{}
	\@for\name:=#1\do{
		\setcounter{pracetmp}{\name}
		\if@praceflag
			\edef\alfalist{\alfalist,\thepracetmp}
		\else
			\edef\alfalist{\thepracetmp}
			\@praceflagtrue
		\fi}
	\@praceflagfalse
	%
%	\def\alfalist{\csvitoa{#1}}
	%
	\def\tmpname{#2}
	\if@iscorresponding
		\edef\tmpname{\tmpname{}${}^{\alfalist{},*}$}
	\else
		\edef\tmpname{\tmpname{}${}^{\alfalist}$}
	\fi
	\ifnum \c@praceauth >\z@
		\edef\authorlist{\authorlist{}, \tmpname{}}
	\else
		\edef\authorlist{\tmpname{}}
	\fi
	\@iscorrespondingfalse
	\addtocounter{praceauth}{1}
}
% store affiliation definitions for later use
\def\affiliationlist{}
\newcommand\affiliation[2][a]{%
	\addtocounter{praceaffi}{1}
	\def\tmpname{{${}^{\thepraceaffi}$#2}}
	\ifnum \c@praceaffi >\@ne
		\edef\affiliationlist{\affiliationlist{},\tmpname{}}
	\else
		\edef\affiliationlist{\tmpname{}}
	\fi%
}
% output affiliation list
\newcommand\affiliationblock[0]{%
	\@for\name:=\affiliationlist\do{\name\\}}

% title block
\renewcommand{\maketitle}{%
  \newpage
	\noindent\begin{minipage}{3cm}
	\includegraphics[width=3cm]{cybersec-logo}
	\end{minipage}
	\begin{minipage}{10.5cm}
	\centering%
	{\large\bfseries CyberSecurity Club at San Francisco State University}
	\end{minipage}
	\begin{minipage}{3cm}
	\end{minipage}\\
  \null
  \vskip 2em%
  \begin{center}%
  \let \footnote \thanks
    {\LARGE \@title \par}%
    \vskip 1.5em%
    {\large
      \lineskip .5em%
      \begin{center}%
        \authorlist
      \end{center}\par}%
    \vskip 1em%
		\affiliationblock
		\if@hascorresponding
			\authorcontact
		\else
			\@latex@warning{Corresponding author is undefined}
		\fi
  \end{center}%
  \par
  \vskip 1.5em%
}

% section heading formats
\def\section{\@startsection {section}{1}{\z@}%
	{-3.0ex \@plus -.8ex \@minus -.2ex}%  beforeskip, corresponding to 18pt in total
	{3.3ex \@plus.7ex}%                   afterskip, corresponding to 18pt in total
	{\normalfont\Large\bfseries}}
\def\subsection{\@startsection{subsection}{2}{\z@}%
	{-3.0ex \@plus -.8ex \@minus -.2ex}%  beforeskip, corresponding to 18pt in total
	{2.0ex \@plus.67ex}%                  afterskip, corresponding to 12pt in total
	{\normalfont\large\bfseries}}
\def\subsubsection{\@startsection{subsubsection}{3}{\z@}%
	{-1.67ex \@plus -.8ex \@minus -.2ex}% beforeskip, corresponding to 12pt in total
	{2.0ex \@plus.67ex}%                  afterskip, corresponding to 12pt in total
	{\normalfont\large\itshape}}
% redefine section, figure etc. format
\RequirePackage{secdot}
\sectiondot{subsection}
\sectiondot{subsubsection}
%\def\thesection       {\arabic{section}}
%\def\thesubsection    {\thesection.\arabic{subsection}}
%\def\thesubsubsection {\thesubsection\arabic{subsection}.}
\def\figurename       {Figure}
\def\tablename        {Table}

% add horizontal lines before and after the abstract
\renewenvironment{abstract}%
	{\noindent\rule{\textwidth}{0.1pt}
	\small
	\noindent{\bfseries \abstractname}
	\quotation}%
 	{\vspace{1em}\\
	\noindent\rule{\textwidth}{0.1pt}}
% no indentation for quotations
\renewenvironment{quotation}%
	{\list{}{%
		\listparindent 0.0em
		\itemindent    \listparindent
		\rightmargin   \leftmargin
		\parsep        \z@ \@plus\p@}%
	\item\relax}
	{\endlist}

% add space either after table caption or before figure caption
\newif\if@withintable
\@withintablefalse
\newif\if@withinfigure
\@withinfigurefalse
\renewenvironment{figure}
	{\@withinfiguretrue\@float{figure}}
	{\end@float\@withinfigurefalse}
\renewenvironment{figure*}
	{\@withinfiguretrue\@dblfloat{figure}}
	{\end@dblfloat\@withinfigurefalse}
\renewenvironment{table}
	{\@withintabletrue\@float{table}}
	{\end@float\@withintablefalse}
\renewenvironment{table*}
	{\@withintabletrue\@dblfloat{table}}
	{\end@dblfloat\@withintablefalse}
\setlength\abovecaptionskip{10\p@}
\setlength\belowcaptionskip{10\p@}
\long\def\@makecaption#1#2{%
	\if@withinfigure
		\vskip\abovecaptionskip
	\fi
	{\small #1. #2\par}
	\if@withintable
		\vskip\belowcaptionskip
	\fi}

% ref.number in References
\def\@biblabel#1{\indent[#1]}
% and changed formatting of heading
\renewenvironment{thebibliography}[1]
     {\subsection*{\refname}% <- changed to match style of subsection
      \@mkboth{\MakeUppercase\refname}{\MakeUppercase\refname}%
      \list{\@biblabel{\@arabic\c@enumiv}}%
           {\settowidth\labelwidth{\@biblabel{#1}}%
            \leftmargin\labelwidth
            \advance\leftmargin\labelsep
            \@openbib@code
            \usecounter{enumiv}%
            \let\p@enumiv\@empty
            \renewcommand\theenumiv{\@arabic\c@enumiv}}%
      \sloppy
      \clubpenalty4000
      \@clubpenalty \clubpenalty
      \widowpenalty4000%
      \sfcode`\.\@m}
     {\def\@noitemerr
       {\@latex@warning{Empty `thebibliography' environment}}%
      \endlist}

% hyperref should be last, I think
\RequirePackage[hidelinks]{hyperref}
