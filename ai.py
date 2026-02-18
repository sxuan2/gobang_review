import numpy as np
import time

EMPTY = 0
BLACK = 1
WHITE = 2
WALL = 3
BOARD_SIZE = 15

SCORE_WIN = 100000000
SCORE_LIVE_FOUR = 1000000
SCORE_BLOCK_FOUR = 200000
SCORE_LIVE_THREE = 50000
SCORE_BLOCK_THREE = 8000
SCORE_LIVE_TWO = 2000

DIRECTIONS = [(0,1),(1,0),(1,1),(1,-1)]


class GomokuAI:

    def __init__(self):
        self.board = np.zeros((BOARD_SIZE, BOARD_SIZE), dtype=int)
        self.start_time = 0
        self.time_limit = 10
        self.max_candidates = 15

    def reset(self):
        self.board = np.zeros((BOARD_SIZE, BOARD_SIZE), dtype=int)

    def is_timeout(self):
        return (time.time() - self.start_time) > self.time_limit

    # =============================
    # 主入口
    # =============================
    def get_best_move(self, player, time_limit=10.0, max_candidates=15):

        self.start_time = time.time()
        self.time_limit = max(1.0, float(time_limit) - 0.8)
        self.max_candidates = int(max_candidates)

        # 空盘
        if np.all(self.board == EMPTY):
            return (7,7), 0

        opponent = 3 - player

        # =============================
        # 1. 一步必胜
        # =============================
        for y in range(BOARD_SIZE):
            for x in range(BOARD_SIZE):
                if self.board[y][x] == EMPTY:
                    self.board[y][x] = player
                    if self.check_win(x,y,player):
                        self.board[y][x] = EMPTY
                        return (x,y), SCORE_WIN
                    self.board[y][x] = EMPTY

        # =============================
        # 2. 一步必堵
        # =============================
        for y in range(BOARD_SIZE):
            for x in range(BOARD_SIZE):
                if self.board[y][x] == EMPTY:
                    self.board[y][x] = opponent
                    if self.check_win(x,y,opponent):
                        self.board[y][x] = EMPTY
                        return (x,y), -SCORE_WIN
                    self.board[y][x] = EMPTY

        # =============================
        # 3. AlphaBeta 搜索
        # =============================
        best_move = None
        best_score = -float("inf")

        depth = 2
        max_depth = 6

        try:
            while depth <= max_depth and not self.is_timeout():
                move, score = self.minimax_root(depth, player)
                if move:
                    best_move = move
                    best_score = score
                depth += 2
        except TimeoutError:
            pass

        if best_move is None:
            return (7,7), 0

        return best_move, int(best_score)

    # =============================
    # 搜索
    # =============================
    def minimax_root(self, depth, player):

        alpha = -float("inf")
        beta = float("inf")

        best_val = -float("inf")
        best_move = None

        candidates = self.get_sorted_candidates(player)

        for (x,y) in candidates:

            if self.is_timeout():
                raise TimeoutError()

            self.board[y][x] = player

            if self.check_win(x,y,player):
                self.board[y][x] = EMPTY
                return (x,y), SCORE_WIN

            val = self.minimax(depth-1, alpha, beta, False, 3-player)

            self.board[y][x] = EMPTY

            if val > best_val:
                best_val = val
                best_move = (x,y)

            alpha = max(alpha, val)

        return best_move, best_val

    def minimax(self, depth, alpha, beta, maximizing, player):

        if self.is_timeout():
            raise TimeoutError()

        if depth == 0:
            return self.evaluate_board(player)

        candidates = self.get_sorted_candidates(player)

        if maximizing:
            value = -float("inf")
            for (x,y) in candidates:
                self.board[y][x] = player
                try:
                    if self.check_win(x,y,player):
                        return SCORE_WIN
                    value = max(value,
                        self.minimax(depth-1, alpha, beta, False, 3-player))
                    alpha = max(alpha, value)
                finally:
                    self.board[y][x] = EMPTY
                if beta <= alpha:
                    break
            return value
        else:
            value = float("inf")
            for (x,y) in candidates:
                self.board[y][x] = player
                try:
                    if self.check_win(x,y,player):
                        return -SCORE_WIN
                    value = min(value,
                        self.minimax(depth-1, alpha, beta, True, 3-player))
                    beta = min(beta, value)
                finally:
                    self.board[y][x] = EMPTY
                if beta <= alpha:
                    break
            return value

    # =============================
    # 候选点
    # =============================
    def get_sorted_candidates(self, player):

        candidates = set()
        stones = np.argwhere(self.board != EMPTY)

        if len(stones) == 0:
            return [(7,7)]

        for sy, sx in stones:
            for dy in range(-2,3):
                for dx in range(-2,3):
                    y = sy + dy
                    x = sx + dx
                    if 0 <= x < BOARD_SIZE and 0 <= y < BOARD_SIZE:
                        if self.board[y][x] == EMPTY:
                            candidates.add((x,y))

        scored = []
        opponent = 3 - player

        for (x,y) in candidates:
            s1 = self.evaluate_point(x,y,player)
            s2 = self.evaluate_point(x,y,opponent)
            scored.append(((x,y), s1 + int(0.9*s2)))

        scored.sort(key=lambda t: t[1], reverse=True)

        return [m for (m,_) in scored[:self.max_candidates]]

    # =============================
    # 评估
    # =============================
    def evaluate_board(self, player):

        opponent = 3-player
        score = 0

        for i in range(BOARD_SIZE):
            score += self.evaluate_line(self.board[i,:], player)
            score -= self.evaluate_line(self.board[i,:], opponent)

            score += self.evaluate_line(self.board[:,i], player)
            score -= self.evaluate_line(self.board[:,i], opponent)

        for k in range(-BOARD_SIZE+1, BOARD_SIZE):
            d1 = np.diag(self.board, k)
            d2 = np.diag(np.fliplr(self.board), k)

            score += self.evaluate_line(d1, player)
            score -= self.evaluate_line(d1, opponent)

            score += self.evaluate_line(d2, player)
            score -= self.evaluate_line(d2, opponent)

        return score

    def evaluate_point(self, x, y, player):

        if self.board[y][x] != EMPTY:
            return -10**9

        self.board[y][x] = player
        try:
            if self.check_win(x,y,player):
                return SCORE_WIN
            score = 0
            for dx,dy in DIRECTIONS:
                line = self.get_line(x,y,dx,dy)
                score += self.evaluate_line(np.array(line), player)
            return score
        finally:
            self.board[y][x] = EMPTY

    def get_line(self, x,y, dx,dy):

        line = []
        for k in range(-4,5):
            nx = x + k*dx
            ny = y + k*dy
            if 0 <= nx < BOARD_SIZE and 0 <= ny < BOARD_SIZE:
                line.append(int(self.board[ny][nx]))
            else:
                line.append(WALL)
        return line

    def evaluate_line(self, line, player):

        s = "".join(map(str, line.tolist()))
        p = str(player)

        if p*5 in s:
            return SCORE_WIN

        score = 0

        if "0"+p*4+"0" in s:
            score += SCORE_LIVE_FOUR

        if p*4 in s:
            score += SCORE_BLOCK_FOUR

        if "0"+p*3+"0" in s:
            score += SCORE_LIVE_THREE

        if p*3 in s:
            score += SCORE_BLOCK_THREE

        if "0"+p*2+"0" in s:
            score += SCORE_LIVE_TWO

        return score

    # =============================
    # 胜负检测
    # =============================
    def check_win(self, x,y, player):

        for dx,dy in DIRECTIONS:
            count = 1

            nx,ny = x+dx,y+dy
            while 0<=nx<BOARD_SIZE and 0<=ny<BOARD_SIZE and self.board[ny][nx]==player:
                count+=1
                nx+=dx
                ny+=dy

            nx,ny = x-dx,y-dy
            while 0<=nx<BOARD_SIZE and 0<=ny<BOARD_SIZE and self.board[ny][nx]==player:
                count+=1
                nx-=dx
                ny-=dy

            if count>=5:
                return True

        return False
