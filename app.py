# coding: utf -8
import PySimpleGUI as sg  # ライブラリの読み込み
import re
import aes

# テーマの設定
# sg.theme("Dark Blue 3 ")

# ドメイン設定
L1 = [
	# 暗号利用モード
	[sg.Text("・暗号利用モード ", size=(20, 1)),
	 sg.OptionMenu(["ECB","CBC", "CTR", "CMAC"],
				   background_color="#ffffff",
				   default_value="ECB",
				   size=(5, 1),
				   key="-MODE-"),
	 sg.OptionMenu(["暗号化", "復号化"],
				   background_color="#ffffff",
				   default_value="暗号化",
				   size=(5, 1),
				   key="-TYPE-")],
	# 鍵値
	[sg.Text("・鍵値 ", size=(20, 1)),
	 sg.InputText(default_text="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				  text_color="#000000",
				  background_color="#ffffff",
				  size=(45, 1),
				  key="-KEY-")],
	# IV
	[sg.Text("・IV ", size=(20, 1)),
	 sg.InputText(default_text="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				  text_color="#000000",
				  background_color="#ffffff",
				  key="-IV-",
				  size=(45, 1))],
	# Nonce
	[sg.Text("・Nonce ", size=(20, 1)),
	 sg.InputText(default_text="FFFFFFFFFFFFFFFF",
				  text_color="#000000",
				  background_color="#ffffff",
				  key="-NONCE-",
				  size=(45, 1))],
	# カウンタ
	[sg.Text("・カウンタ ", size=(20, 1)),
	 sg.InputText(default_text="0",
				  text_color="#000000",
				  background_color="#ffffff",
				  key="-COUNTER-",
				  size=(45, 1))],
	# 入力値(平文 0r 暗号)
	[sg.Text("・入力値 (平文 or 暗号文)", size=(40, 1))],
	[sg.Multiline(default_text="",
				  text_color="#000000",
				  background_color="#ffffff",
				  size=(100, 10),
				  key="-INPUT_TXT-")],
	# 出力値
	[sg.Text("・出力値 (平文 or 暗号文 or MAC)", size=(40, 1))],
	[sg.Multiline(default_text="",
				  text_color="#000000",
				  # background_color="#ffff00",
				  size=(100, 10),
				  key="-OUTPUT_TXT-")],
	[sg.Button("実行", border_width=4, size=(15, 1), key="aes_start")]]
# ウィンドウ作成
window = sg.Window("AES_TOOL ", L1)


def main():
	# イベントループ
	while True:
		# イベントの読み取り（イベント待ち）
		event, values = window.read()
		if event == "aes_start":
			# 不要要素の削除
			input_txt = re.sub('[^0123456789abcdefABCDEF]', '', values["-INPUT_TXT-"])
			# テキストサイズチェック
			if 0 == ( len(input_txt) % 2 ):
				input_txt = bytes.fromhex(input_txt)
				key = bytes.fromhex(re.sub('[^0123456789abcdefABCDEF]', '', values["-KEY-"]))
				output_txt = ""
				if   "ECB" == values["-MODE-"]:
					if "暗号化" == values["-TYPE-"]:
						output_txt = aes.aes_ecb_enc_fnc( key , input_txt )
					else:
						output_txt = aes.aes_ecb_dec_fnc( key , input_txt )
				elif "CBC" == values["-MODE-"]:
					if "暗号化" == values["-TYPE-"]:
						output_txt = aes.aes_cbc_enc_fnc( key , input_txt , bytes.fromhex(re.sub('[^0123456789abcdefABCDEF]', '', values["-IV-"]) ))
					else:
						output_txt = aes.aes_cbc_dec_fnc( key , input_txt , bytes.fromhex(re.sub('[^0123456789abcdefABCDEF]', '', values["-IV-"]) ))
				elif "CTR" == values["-MODE-"]:
					if "暗号化" == values["-TYPE-"]:
						output_txt = aes.aes_ctr_enc_fnc( key , input_txt , bytes.fromhex(re.sub('[^0123456789abcdefABCDEF]', '', values["-NONCE-"])) , int(values["-COUNTER-"]) )
					else:
						output_txt = aes.aes_ctr_dec_fnc( key , input_txt , bytes.fromhex(re.sub('[^0123456789abcdefABCDEF]', '', values["-NONCE-"])) , int(values["-COUNTER-"]) )
				elif "CMAC" == values["-MODE-"]:
					output_txt = aes.aes_cmac_fnc( key , input_txt )

				window["-OUTPUT_TXT-"].Update(output_txt.hex())
			else:
				window["-OUTPUT_TXT-"].Update("入力値不正")

		# 終了条件（ None: クローズボタン）
		elif event is None:
			break
	# 終了処理
	window.close()


if __name__ == '__main__':
	main()


