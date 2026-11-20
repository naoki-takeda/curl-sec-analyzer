// ui/message.ts：状態のメッセージ（件数、入力がない、読み込みのエラーなど。役割 status の refs.message）
// 文言を作る関数で受け取り、言語を切り替えたらその言語で出し直す（文字列のまま残すと、英語の画面に日本語のメッセージが残る）
import { type Message, refs } from './state';

let current: Message | undefined;
/** メッセージを出す。引数なしで消す */
export function say(m?: Message) { current = m; refs.message.textContent = m ? m() : ''; }
/** 出しているメッセージ（言語の切り替え・判定し直しのあとに出し直すため） */
export const currentMessage = (): Message | undefined => current;
/** 2つのメッセージを続けて出す（後ろが空なら前だけ） */
export const joined = (a: Message, b?: Message): Message => (b ? () => `${a()} ${b()}` : a);
